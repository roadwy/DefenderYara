
rule Trojan_Win64_Winnti_ZB_dha{
	meta:
		description = "Trojan:Win64/Winnti.ZB!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b1 99 48 85 db 7e 90 01 01 48 8b c7 30 08 40 02 ce 48 03 c6 48 2b de 75 90 00 } //01 00 
		$a_01_1 = {48 83 64 24 30 00 45 33 c9 44 8b c6 ba 00 00 00 40 49 8b cd c7 44 24 28 80 00 00 00 c7 44 24 20 04 00 00 00 ff 15 } //01 00 
		$a_01_2 = {41 0f b6 11 41 ff c2 49 ff c1 80 f2 31 0f b6 c2 c0 ea 04 c0 e0 04 02 c2 41 88 41 ff 44 3b 56 0e 72 } //01 00 
		$a_03_3 = {ff d8 ff e0 00 00 00 00 00 00 90 02 64 e9 ea eb ec ed ee ef f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}