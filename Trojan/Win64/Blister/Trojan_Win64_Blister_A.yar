
rule Trojan_Win64_Blister_A{
	meta:
		description = "Trojan:Win64/Blister.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 44 0f b7 db 48 8b 48 18 48 8b 41 30 } //04 00 
		$a_03_1 = {41 8b 0a 8b d3 49 03 90 01 01 8a 01 84 c0 90 00 } //04 00 
		$a_01_2 = {c1 c2 09 0f be c0 03 d0 8a 01 84 c0 } //04 00 
		$a_03_3 = {48 8b c3 49 03 90 01 01 83 e0 03 8a 44 90 01 02 41 30 90 01 01 4d 03 90 00 } //04 00 
		$a_03_4 = {ff d6 48 8d 87 90 01 02 00 00 48 8d 90 02 03 ff d0 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 92 09 05 80 5c 2f 00 00 } //93 09 
	condition:
		any of ($a_*)
 
}