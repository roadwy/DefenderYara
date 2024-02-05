
rule Trojan_Win32_Gozi_PAC_MTB{
	meta:
		description = "Trojan:Win32/Gozi.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 0f 83 c7 04 01 1d 90 01 04 0f af d0 a1 90 01 04 8b ca c1 e9 08 88 0c 30 8b 0d 90 01 04 a1 90 01 04 41 89 0d 90 01 04 88 14 08 8b 15 90 01 04 8b c2 33 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}