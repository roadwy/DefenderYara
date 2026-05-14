
rule Trojan_BAT_Heracles_BAL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 4b 00 02 08 18 ?? ?? ?? 00 0a 1f 10 ?? ?? ?? 00 0a 03 07 ?? ?? ?? 00 0a ?? ?? ?? 00 0a 61 ?? ?? ?? 00 0a 13 04 12 04 ?? ?? ?? 00 0a 0d 06 09 ?? ?? ?? 00 0a 26 07 03 ?? ?? ?? 00 0a 17 59 2e 05 07 17 58 2b 01 16 0b 00 08 18 58 0c 08 02 ?? ?? ?? 00 0a fe 04 13 05 11 05 2d a6 } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Heracles_BAL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 05 00 fe 0c 04 00 20 00 00 00 00 73 16 03 00 0a fe 0e 06 00 fe 0c 06 00 73 35 03 00 0a fe 0e 07 00 fe 0c 07 00 ?? ?? ?? 00 0a fe 0e 00 00 dd 39 00 00 00 fe 0c 07 00 39 09 00 00 00 fe 0c 07 00 ?? ?? 00 00 0a dc fe 0c 06 00 39 09 00 00 00 fe 0c 06 00 ?? ?? 00 00 0a dc fe 0c 05 00 39 09 00 00 00 fe 0c 05 00 ?? ?? 00 00 0a dc } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}