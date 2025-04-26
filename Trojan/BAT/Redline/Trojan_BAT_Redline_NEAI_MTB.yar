
rule Trojan_BAT_Redline_NEAI_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 1b 59 8d 77 00 00 01 0a 02 1b 06 16 02 8e 69 1b 59 28 2f 01 00 0a 06 16 14 28 bf 00 00 06 0b 25 03 6f da 00 00 0a 07 28 9b 00 00 06 6f 6a 00 00 0a 2a } //10
		$a_01_1 = {45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 73 } //2 ExpandEnvironmentVariables
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}