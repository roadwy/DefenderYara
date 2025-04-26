
rule Trojan_BAT_XWorm_MBJS_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MBJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 33 38 63 34 66 39 62 35 2d 61 30 38 34 2d 34 63 31 34 2d 62 65 62 65 2d 61 37 36 39 30 66 38 64 34 62 31 65 } //10 $38c4f9b5-a084-4c14-bebe-a7690f8d4b1e
		$a_01_1 = {24 30 33 38 63 65 36 38 33 2d 32 32 35 35 2d 34 34 32 63 2d 38 36 37 34 2d 36 32 65 38 63 66 65 38 35 39 35 34 } //10 $038ce683-2255-442c-8674-62e8cfe85954
		$a_01_2 = {58 43 6c 69 65 6e 74 2e 65 78 65 } //1 XClient.exe
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}