
rule Trojan_Win32_SmokeLoader_MP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 90 01 45 08 8b 45 08 89 01 5d c2 08 } //00 00 
	condition:
		any of ($a_*)
 
}