
rule Trojan_Win64_Lazy_NLS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {eb 05 48 ff c9 75 be 48 83 ec 28 48 8d be 90 01 04 8b 07 09 c0 74 4a 8b 5f 04 48 8d 8c 30 90 01 04 48 01 f3 48 83 c7 08 ff 96 0c d2 00 00 48 95 8a 07 48 ff c7 08 c0 74 d7 90 00 } //01 00 
		$a_01_1 = {57 6f 77 4f 70 4f 2e 54 58 54 } //00 00  WowOpO.TXT
	condition:
		any of ($a_*)
 
}