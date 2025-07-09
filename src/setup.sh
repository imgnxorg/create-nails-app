#!/bin/bash
set -e

# Step 1: Create Next.js + TailwindCSS app
npx create-next-app@latest frontend -e app-tw --typescript --src-dir

# Step 2: Configure static export
cat > frontend/next.config.js <<EOF
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
}
export default nextConfig;
EOF

# Step 3: Build and export
cd frontend
npm install
npm run build
npm run export

# Step 4: Prepare Wails static folder
mkdir -p ../frontend/dist
cp -r out/* ../frontend/dist/

echo "✅ Next.js static build ready in frontend/dist"
