
rule Trojan_BAT_Remcos_RED_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 90 01 03 0a de 03 26 de 00 00 73 90 01 03 0a 0a 02 73 90 01 03 0a 0b 06 07 6f 90 01 03 0a 0c de 0d 06 2c 06 06 6f 90 01 03 0a dc 26 de db 90 00 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}