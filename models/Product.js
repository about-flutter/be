const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  description: { type: String },
  image: [{ type: String }],  // URL hình ảnh (từ Cloudinary hoặc tương tự)
  category: { type: String },
  countInStock: { type: Number, required: true, default: 0 },
}, { timestamps: true });

module.exports = mongoose.model('Product', productSchema);