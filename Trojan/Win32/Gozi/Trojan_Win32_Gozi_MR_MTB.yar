
rule Trojan_Win32_Gozi_MR_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 57 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 8b 02 a3 90 01 04 8b 0d 90 01 04 81 e9 90 01 04 89 0d 90 01 04 8b 0d 90 01 04 81 c1 90 01 04 a1 90 01 04 a3 90 00 } //01 00 
		$a_02_1 = {8b ff 8b 15 90 01 04 a1 90 01 04 89 02 5f 5b 5d c3 90 09 11 00 ff c7 05 90 01 08 01 05 90 00 } //01 00 
		$a_02_2 = {03 f0 8b 55 90 01 01 03 32 8b 45 90 01 01 89 30 8b 4d 90 01 01 8b 11 81 ea 90 01 04 8b 45 90 01 01 89 10 5e 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}