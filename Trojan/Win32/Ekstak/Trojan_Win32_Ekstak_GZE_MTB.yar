
rule Trojan_Win32_Ekstak_GZE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 57 89 65 e8 a0 90 01 04 32 05 90 01 04 24 90 01 01 a2 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 8d 14 4a 89 15 90 01 04 8b 15 90 01 04 83 e2 03 33 db 8a d8 0f af d3 03 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}