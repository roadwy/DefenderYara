
rule Trojan_BAT_QuasarRat_NEAN_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 30 33 30 66 65 36 37 2d 38 61 64 65 2d 34 30 65 63 2d 39 30 66 66 2d 63 35 36 39 61 33 63 30 34 36 62 32 } //5 4030fe67-8ade-40ec-90ff-c569a3c046b2
		$a_01_1 = {76 62 73 2e 65 78 65 } //2 vbs.exe
		$a_01_2 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //2 WScript.Shell
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}