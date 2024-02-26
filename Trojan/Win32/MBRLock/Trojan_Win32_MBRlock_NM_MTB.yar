
rule Trojan_Win32_MBRlock_NM_MTB{
	meta:
		description = "Trojan:Win32/MBRlock.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 05 e0 bd 4c 00 90 01 04 8d 86 80 04 00 00 3b f0 73 1e 80 66 04 90 01 01 83 0e ff 83 66 08 90 01 01 c6 46 05 0a a1 90 01 04 83 c6 24 05 90 01 04 eb de 8d 45 b8 90 00 } //01 00 
		$a_01_1 = {5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //00 00  \physicaldrive0
	condition:
		any of ($a_*)
 
}