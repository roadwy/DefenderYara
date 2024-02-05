
rule Trojan_Win32_SmokeLoader_RB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 a9 2a 6f db ad 44 ad 44 a8 68 ea 53 af af af af 44 a2 9c 90 5a } //00 00 
	condition:
		any of ($a_*)
 
}