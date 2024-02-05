
rule Trojan_Win32_Delfinject_RW_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 10 00 00 a1 90 01 04 50 8b 06 8d 04 80 8b 15 90 01 04 8b 44 c2 90 01 01 03 05 90 01 04 50 e8 90 01 04 a3 90 00 } //01 00 
		$a_03_1 = {f6 c4 f0 74 90 01 01 8b 1d 90 01 04 8b 1b 03 1d 90 01 04 66 25 ff 0f 0f b7 c0 03 d8 a1 90 01 04 01 03 83 01 02 ff 05 90 01 04 4a 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}