
rule Trojan_BAT_Nanocore_ABZV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //2
		$a_01_1 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62 00 } //1 DataBasePracticalJob
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}