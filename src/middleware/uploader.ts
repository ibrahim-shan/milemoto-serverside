import multer from 'multer';

// Configure multer to store files in memory (as a Buffer)
// We set a 5MB file size limit to prevent abuse.
const storage = multer.memoryStorage();
export const uploadJson = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/json') {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JSON is allowed.'));
    }
  },
});
