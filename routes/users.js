var express = require("express");
var router = express.Router();
let bcrypt = require('bcrypt')
let { userPostValidation, validateResult } =
  require('../utils/validationHandler')
let { checkLogin,checkRole } = require('../utils/authHandler')
let userModel = require("../schemas/users");

let userController = require("../controllers/users");


router.get("/", checkLogin,checkRole("ADMIN") , async function (req, res, next) {
  let result = await userController.getAllUser();
  res.send(result)
});

router.get("/:id", checkLogin,checkRole("ADMIN","MODERATOR"), async function (req, res, next) {
  try {
    let result = await userController.FindByID(req.params.id)
    if (result) {
      res.send(result);
    }
    else {
      res.status(404).send({ message: "id not found" });
    }
  } catch (error) {
    res.status(404).send({ message: "id not found" });
  }
});

router.post("/", userPostValidation, validateResult,
  async function (req, res, next) {
    try {
      let newItem = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        req.body.role,
        "", "",
        false
      )
      // populate cho đẹp
      let saved = await userController.FindByID(newItem._id);
      res.send(saved);
    } catch (err) {
      res.status(400).send({ message: err.message });
    }
  });

router.put("/:id", checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findOne({ _id: id, isDeleted: false })
    if (!updatedItem) return res.status(404).send({ message: "id not found" });
    let keys = Object.keys(req.body);
    for (const key of keys) {
      updatedItem[key] = req.body[key];
    }
    await updatedItem.save();
    let populated = await userModel
      .findById(updatedItem._id)
    res.send(populated);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

router.delete("/:id", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    if (!updatedItem) {
      return res.status(404).send({ message: "id not found" });
    }
    res.send(updatedItem);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

router.put("/:id/change-password", checkLogin, async function (req, res, next) {
  try {
    let { oldPassword, newPassword } = req.body;
    let id = req.userId;
    
    if (!oldPassword || !newPassword) {
      return res.status(400).send({ message: "oldPassword và newPassword là bắt buộc" });
    }

    let user = await userController.FindByID(id);
    if (!user) {
      return res.status(404).send({ message: "Người dùng không tồn tại" });
    }

    let isPasswordValid = bcrypt.compareSync(oldPassword, user.password);
    if (!isPasswordValid) {
      return res.status(403).send({ message: "Mật khẩu cũ không chính xác" });
    }

    let updatedUser = await userModel.findByIdAndUpdate(
      id,
      { password: newPassword },
      { new: true }
    );

    res.send({ message: "Đổi mật khẩu thành công", user: updatedUser });
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

module.exports = router;