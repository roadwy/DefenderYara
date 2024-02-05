
rule Trojan_Win32_PackZ_AMAA_MTB{
	meta:
		description = "Trojan:Win32/PackZ.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 cb 41 8d 3c 07 bb 90 01 04 89 cb 8b 3f 21 c9 01 d9 21 db 81 e7 ff 00 00 00 81 c3 90 01 04 b9 90 01 04 81 c3 01 00 00 00 40 09 cb 81 e9 90 01 04 81 f8 f4 01 00 00 75 90 01 01 b8 00 00 00 00 81 c3 01 00 00 00 21 c9 49 01 db 29 d9 4b 31 3a 89 cb bb 90 01 04 81 c2 02 00 00 00 89 d9 29 cb 81 e9 90 01 04 39 f2 90 00 } //01 00 
		$a_03_1 = {8a 07 09 d9 09 c9 88 06 21 cb 09 c9 bb 90 01 04 46 81 c1 90 01 04 81 c3 90 01 04 81 c3 01 00 00 00 81 c7 02 00 00 00 01 cb 43 39 d7 0f 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}