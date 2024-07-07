
rule Trojan_VBA_Downldr_CX_MTB{
	meta:
		description = "Trojan:VBA/Downldr.CX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 6f 72 72 79 66 6f 72 74 68 65 2e 69 6e 66 6f 2f 70 72 69 76 61 74 65 2f 48 4b 5f 53 6b 79 6c 69 6e 65 2e 6a 70 67 } //2 sorryforthe.info/private/HK_Skyline.jpg
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 69 6d 67 73 72 63 2c 20 64 6c 70 61 74 68 20 26 20 22 48 4b 5f 53 6b 79 6c 69 6e 65 2e 6a 70 67 } //1 URLDownloadToFile 0, imgsrc, dlpath & "HK_Skyline.jpg
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}