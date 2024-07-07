
rule Trojan_BAT_Barys_ABR_MTB{
	meta:
		description = "Trojan:BAT/Barys.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 02 08 07 06 1b 16 09 28 0f 00 00 06 26 06 6f 18 00 00 0a 13 } //2
		$a_01_1 = {4c 00 69 00 6d 00 65 00 4c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 LimeLogger.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}