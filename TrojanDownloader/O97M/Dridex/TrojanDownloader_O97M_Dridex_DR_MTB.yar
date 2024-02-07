
rule TrojanDownloader_O97M_Dridex_DR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 68 74 53 37 51 39 57 74 70 73 3a 2f 2f 76 6f 79 53 37 51 39 57 79 61 2e 63 6f 6d 53 37 51 39 57 2e 6d 78 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 44 69 76 69 2f 69 6e 63 6c 75 53 37 51 39 57 64 65 73 2f 53 37 51 39 57 53 37 51 39 57 62 75 69 6c 64 65 72 2f 46 76 31 34 78 67 70 65 4c 65 38 73 37 67 7a 2e 70 68 70 22 2c 20 22 53 37 51 39 57 22 2c 20 22 22 29 } //01 00  Replace("htS7Q9Wtps://voyS7Q9Wya.comS7Q9W.mx/wp-content/themes/Divi/incluS7Q9Wdes/S7Q9WS7Q9Wbuilder/Fv14xgpeLe8s7gz.php", "S7Q9W", "")
		$a_01_1 = {52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 62 69 74 63 6f 69 6e 73 6f 63 69 65 74 5a 77 2f 5a 49 3a 7a 79 2e 72 62 72 65 76 69 65 77 73 2e 69 6e 2f 66 6f 6e 74 73 2f 37 70 50 31 4b 7a 37 74 39 4a 51 50 2e 70 68 70 22 2c 20 22 5a 77 2f 5a 49 3a 7a 22 2c 20 22 22 29 } //01 00  Replace("https://bitcoinsocietZw/ZI:zy.rbreviews.in/fonts/7pP1Kz7t9JQP.php", "Zw/ZI:z", "")
		$a_01_2 = {52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 72 2c 62 47 37 75 37 74 65 63 68 66 6f 72 63 65 64 78 62 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 72 2c 62 47 37 75 37 67 69 6e 73 2f 77 6f 72 64 72 2c 62 47 37 75 37 72 2c 62 47 37 75 37 70 72 65 73 73 2d 73 65 6f 2f 73 72 63 2f 63 6f 6e 66 69 67 72 2c 62 47 37 75 37 2f 4b 34 49 42 4a 37 76 4c 4e 37 6b 72 2c 62 47 37 75 37 77 4d 2e 70 68 70 22 2c 20 22 72 2c 62 47 37 75 37 22 2c 20 22 22 29 } //01 00  Replace("https://r,bG7u7techforcedxb.com/wp-content/plur,bG7u7gins/wordr,bG7u7r,bG7u7press-seo/src/configr,bG7u7/K4IBJ7vLN7kr,bG7u7wM.php", "r,bG7u7", "")
		$a_01_3 = {52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 65 76 6f 6c 76 69 6e 67 64 65 73 6b 2e 6e 75 73 5e 6a 6a 73 28 6c 2f 47 6f 6f 67 6c 65 41 50 49 2f 76 65 6e 64 6f 72 2f 73 79 6d 66 6f 6e 79 2f 70 6f 75 73 5e 6a 6a 73 28 6c 79 66 69 6c 6c 2d 69 6e 74 6c 2d 6e 6f 72 6d 61 6c 69 7a 65 72 2f 52 65 73 6f 75 72 63 65 73 2f 4a 73 57 50 75 73 5e 6a 6a 73 28 56 4c 5a 77 39 71 72 39 47 46 45 2e 70 68 70 22 2c 20 22 75 73 5e 6a 6a 73 28 22 2c 20 22 22 29 } //00 00  Replace("https://evolvingdesk.nus^jjs(l/GoogleAPI/vendor/symfony/pous^jjs(lyfill-intl-normalizer/Resources/JsWPus^jjs(VLZw9qr9GFE.php", "us^jjs(", "")
	condition:
		any of ($a_*)
 
}