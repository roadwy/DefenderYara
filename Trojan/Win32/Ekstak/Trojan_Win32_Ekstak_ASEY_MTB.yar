
rule Trojan_Win32_Ekstak_ASEY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 68 34 10 65 00 e8 90 01 03 ff 83 c4 04 a3 90 00 } //05 00 
		$a_03_1 = {e5 64 00 50 ff 15 90 01 01 e5 64 00 f7 d8 1b c0 f7 d8 c3 90 00 } //05 00 
		$a_03_2 = {50 ff d6 68 90 01 03 00 50 ff d7 8b 0d 90 01 03 00 a3 90 01 03 00 51 ff d6 68 90 01 03 00 50 ff d7 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}