/** @type {import('tailwindcss').Config} */
module.exports = {
	content: ["./**/*.html"],
	theme: {
		extend: {
			keyframes: {
				shine: {
					"0%": { left: "-100%" },
					"50%": { left: "150%" },
					"100%": { left: "150%" },
				},
			},
			animation: {
				shine: "shine 2s linear infinite",
			},
		},
	},
	plugins: [],
};
