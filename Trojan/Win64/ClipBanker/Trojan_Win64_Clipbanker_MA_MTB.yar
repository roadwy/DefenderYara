
rule Trojan_Win64_Clipbanker_MA_MTB{
	meta:
		description = "Trojan:Win64/Clipbanker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 89 ee 48 81 c6 3f 01 00 00 48 8b 36 48 81 c6 09 00 00 00 4c 0f b7 2e 48 89 e8 48 05 2f 00 00 00 44 03 28 49 89 ef 49 81 c7 6f 01 00 00 45 03 2f 49 89 ef 49 81 c7 2f 00 00 00 45 21 2f 48 89 ea 48 81 c2 dd 00 00 00 48 89 eb 48 81 c3 2c 00 00 00 40 8a 3b } //00 00 
	condition:
		any of ($a_*)
 
}