
rule Trojan_Win32_SmokeLoader_SUB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 1e 46 3b f7 7c da } //00 00 
	condition:
		any of ($a_*)
 
}