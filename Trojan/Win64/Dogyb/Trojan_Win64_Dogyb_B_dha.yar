
rule Trojan_Win64_Dogyb_B_dha{
	meta:
		description = "Trojan:Win64/Dogyb.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 41 64 64 2e 64 6c 6c 00 41 64 64 42 79 47 6f 64 00 } //01 00  䄀摤搮汬䄀摤祂潇d
		$a_00_1 = {48 8d 45 00 ff 10 } //01 00 
		$a_02_2 = {ba 10 66 00 00 90 02 08 41 b9 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}