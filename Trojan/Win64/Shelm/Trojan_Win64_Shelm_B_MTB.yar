
rule Trojan_Win64_Shelm_B_MTB{
	meta:
		description = "Trojan:Win64/Shelm.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 48 8d 0d e5 11 00 00 e8 90 } //02 00 
		$a_03_1 = {ff 33 c9 ba 90 01 04 41 b8 00 10 00 00 44 8d 49 40 ff 15 69 0f 00 00 48 8d 0d 90 01 04 41 b8 90 01 04 4c 8b c8 48 8b d0 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}