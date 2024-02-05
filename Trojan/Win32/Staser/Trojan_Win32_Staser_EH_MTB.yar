
rule Trojan_Win32_Staser_EH_MTB{
	meta:
		description = "Trojan:Win32/Staser.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 07 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 8b 75 14 3b 7d 0c a9 00 00 80 00 56 } //01 00 
		$a_01_1 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 4e 61 6d 65 41 } //01 00 
		$a_01_2 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}