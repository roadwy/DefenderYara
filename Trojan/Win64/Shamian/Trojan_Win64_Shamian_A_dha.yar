
rule Trojan_Win64_Shamian_A_dha{
	meta:
		description = "Trojan:Win64/Shamian.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {6d 61 69 6e 2e 58 6f 72 44 65 63 6f 64 65 53 74 72 } //01 00  main.XorDecodeStr
		$a_01_2 = {6d 61 69 6e 2e 69 6e 69 74 } //01 00  main.init
		$a_01_3 = {2f 6d 69 61 6e 73 68 61 2f 78 78 32 2e 67 6f } //00 00  /miansha/xx2.go
	condition:
		any of ($a_*)
 
}