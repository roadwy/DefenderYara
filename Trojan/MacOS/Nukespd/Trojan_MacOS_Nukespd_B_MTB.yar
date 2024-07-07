
rule Trojan_MacOS_Nukespd_B_MTB{
	meta:
		description = "Trojan:MacOS/Nukespd.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 63 68 65 2d 65 67 2e 6f 72 67 2f 70 6c 75 67 69 6e 73 2f 74 6f 70 2e 70 68 70 } //2 sche-eg.org/plugins/top.php
		$a_00_1 = {41 b9 e8 03 00 00 41 f7 f9 48 8b bd 58 ff ff ff 4c 8b 85 60 ff ff ff 89 95 28 ff ff ff 4c 89 c2 4c 8d 1d 51 4b 00 00 48 89 8d 20 ff ff ff 4c 89 d9 4c 8b 85 68 ff ff ff 44 8b 8d 54 ff ff ff 44 8b 95 50 ff ff ff 44 89 14 24 44 8b 95 4c ff ff ff 44 89 54 24 08 44 8b 95 34 ff ff ff 44 89 54 24 10 4c 8b 9d 38 ff ff ff 4c 89 5c 24 18 } //4
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*4) >=6
 
}