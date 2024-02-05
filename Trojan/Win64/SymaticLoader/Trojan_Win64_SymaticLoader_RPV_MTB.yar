
rule Trojan_Win64_SymaticLoader_RPV_MTB{
	meta:
		description = "Trojan:Win64/SymaticLoader.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 01 48 8d 49 01 2c 0a 34 cc 88 41 ff 48 83 ea 01 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}