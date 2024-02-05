
rule Trojan_Win32_Cobaltstrike_UIP_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.UIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b c3 44 88 1a 41 ff c3 83 e0 03 49 83 c0 04 48 ff c2 45 3b d9 0f b6 04 08 41 89 40 fc } //00 00 
	condition:
		any of ($a_*)
 
}