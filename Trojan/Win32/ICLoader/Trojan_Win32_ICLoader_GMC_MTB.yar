
rule Trojan_Win32_ICLoader_GMC_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a1 04 28 46 01 89 35 1c 13 46 01 8b fe 38 18 74 90 01 01 8b f8 8d 45 f8 50 8d 45 fc 90 00 } //01 00 
		$a_01_1 = {40 2e 64 63 73 38 31 31 } //00 00  @.dcs811
	condition:
		any of ($a_*)
 
}