
rule Trojan_Win32_Ditertag_MR_MTB{
	meta:
		description = "Trojan:Win32/Ditertag.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 55 90 01 01 03 55 f0 8b 45 90 01 01 8b 4d 90 01 01 8a 0c 31 88 0c 10 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 eb 90 09 27 00 b8 90 01 04 85 c0 74 90 01 01 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 8b 75 90 01 01 03 75 90 01 01 68 90 01 04 ff 15 90 00 } //01 00 
		$a_02_1 = {8b ff c7 05 90 01 08 a1 90 01 04 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 09 0b 00 a1 90 01 04 31 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}