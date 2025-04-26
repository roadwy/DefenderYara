
rule Trojan_BAT_Marsilia_MMC_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 02 00 00 06 28 06 00 00 06 2a } //2
		$a_02_1 = {53 6c 69 76 [0-0f] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}