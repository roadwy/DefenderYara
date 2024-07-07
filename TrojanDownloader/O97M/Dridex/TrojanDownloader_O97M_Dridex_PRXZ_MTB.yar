
rule TrojanDownloader_O97M_Dridex_PRXZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PRXZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4d 69 64 28 22 24 3e 3d 4c 5e 49 66 73 2e 71 7a 67 49 76 68 74 74 70 73 3a 2f 2f 67 61 6e 63 68 6f 68 69 67 69 65 6e 69 63 6f 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 62 72 69 64 67 65 2d 63 6f 72 65 2f 6d 6f 64 75 6c 65 73 2f 63 6f 72 65 2d 64 61 73 68 62 6f 61 72 64 2f 52 42 5a 59 79 31 5a 6c 2e 70 68 70 } //1 = Mid("$>=L^Ifs.qzgIvhttps://ganchohigienico.com/wp-content/plugins/bridge-core/modules/core-dashboard/RBZYy1Zl.php
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 79 6f 75 72 63 6f 64 65 6c 6f 56 6a 5c 6f 69 62 65 72 64 61 64 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 50 48 50 4d 61 69 6c 65 6f 56 6a 5c 6f 72 5f 35 2e 32 2e 30 2f 74 65 73 74 5f 73 63 72 69 70 74 2f 69 6d 61 6f 56 6a 5c 6f 67 65 73 2f 79 53 63 35 65 6d 6f 56 6a 5c 6f 67 6e 36 79 69 65 75 64 6f 56 6a 5c 6f 6f 2e 70 68 70 22 2c } //1 = Replace("https://yourcodeloVj\oiberdade.com/mail/PHPMaileoVj\or_5.2.0/test_script/imaoVj\oges/ySc5emoVj\ogn6yieudoVj\oo.php",
		$a_01_2 = {3d 20 4d 69 64 28 22 3d 73 2e 33 6f 43 51 31 4d 6b 2f 3c 62 3e 2c 58 68 74 74 70 73 3a 2f 2f 73 68 61 72 6d 69 6e 61 2e 73 68 61 72 6d 69 6e 61 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 61 6c 6c 2d 69 6e 2d 6f 6e 65 2d 77 70 2d 6d 69 67 72 61 74 69 6f 6e 2f 6c 69 62 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2f 39 4d 75 55 4a 47 67 5a 71 6a 2e 70 68 70 } //1 = Mid("=s.3oCQ1Mk/<b>,Xhttps://sharmina.sharmina.org/wp-content/plugins/all-in-one-wp-migration/lib/controller/9MuUJGgZqj.php
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 3d 70 77 46 65 74 70 73 3a 2f 2f 61 6c 61 72 6d 65 6d 75 73 69 63 61 6c 65 73 63 6f 6c 61 72 2e 68 69 76 65 77 65 62 2e 63 6f 6d 2e 62 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 77 6f 72 64 70 72 65 73 73 3d 70 77 46 65 2d 73 65 6f 3d 70 77 46 65 2f 70 61 63 6b 61 67 65 73 2f 6a 73 2f 73 58 30 49 58 71 59 73 42 51 2e 70 68 70 22 2c } //1 = Replace("ht=pwFetps://alarmemusicalescolar.hiveweb.com.br/wp-content/plugins/wordpress=pwFe-seo=pwFe/packages/js/sX0IXqYsBQ.php",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}