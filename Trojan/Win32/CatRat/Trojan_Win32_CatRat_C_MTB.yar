
rule Trojan_Win32_CatRat_C_MTB{
	meta:
		description = "Trojan:Win32/CatRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 b4 47 c6 45 b5 65 c6 45 b6 74 c6 45 b7 46 c6 45 b8 69 c6 45 b9 6c c6 45 ba 65 c6 45 bb 53 c6 45 bc 69 c6 45 bd 7a c6 45 be 65 c6 45 bf 00 8d 55 b4 52 8b 45 f8 50 ff 55 f4 } //01 00 
		$a_01_1 = {c6 45 c0 43 c6 45 c1 6c c6 45 c2 6f c6 45 c3 73 c6 45 c4 65 c6 45 c5 48 c6 45 c6 61 c6 45 c7 6e c6 45 c8 64 c6 45 c9 6c c6 45 ca 65 c6 45 cb 00 } //01 00 
		$a_01_2 = {8b 45 fc 99 f7 7d dc 8b 45 88 0f be 0c 10 8b 55 d8 03 55 fc 0f be 02 33 c1 8b 4d d8 03 4d fc 88 01 eb c9 } //00 00 
	condition:
		any of ($a_*)
 
}