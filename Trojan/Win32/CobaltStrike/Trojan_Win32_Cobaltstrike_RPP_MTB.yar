
rule Trojan_Win32_Cobaltstrike_RPP_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 c1 89 c8 0f af 45 e4 01 d0 89 c2 8b 45 d8 01 d0 0f b6 00 31 f0 88 03 83 45 e0 01 83 45 e4 01 8b 45 e0 3b 45 0c 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}