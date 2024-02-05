
rule Trojan_Win32_Kryptik_RA_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 8b 55 90 01 01 03 55 90 01 01 0f be 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 55 90 01 01 83 ea 01 89 55 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}