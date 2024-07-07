
rule Trojan_BAT_Exnet_AX_MTB{
	meta:
		description = "Trojan:BAT/Exnet.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 6f 90 01 03 0a 0b 73 1f 00 00 0a 0c 08 03 6f 90 01 03 0a 0d 07 28 90 01 03 0a 13 04 11 04 72 5b 4b 00 70 6f 90 01 03 0a 13 05 72 77 4b 00 70 13 06 18 8d 90 01 03 01 25 16 11 06 a2 25 17 09 a2 13 07 11 05 72 e9 4b 00 70 20 00 01 00 00 14 14 11 07 6f 90 00 } //2
		$a_01_1 = {76 00 61 00 72 00 65 00 73 00 61 00 69 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 varesaint.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}