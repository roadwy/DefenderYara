
rule Trojan_Win32_Vidar_NH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6c 69 6d 61 74 65 6a 75 73 74 69 63 65 2e 73 6f 63 69 61 6c 2f 40 66 66 6f 6c 65 67 39 34 } //01 00  climatejustice.social/@ffoleg94
		$a_01_1 = {74 2e 6d 65 2f 6b 6f 72 73 74 6f 6e 73 61 6c 65 73 } //01 00  t.me/korstonsales
		$a_01_2 = {25 73 5c 25 73 5c 2a 77 61 6c 6c 65 74 2a 2e 64 61 74 } //01 00  %s\%s\*wallet*.dat
		$a_01_3 = {69 6e 64 65 78 65 64 64 62 2e 6c 65 76 65 6c 64 62 } //01 00  indexeddb.leveldb
		$a_01_4 = {5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 } //00 00  \Bitcoin\wallets
	condition:
		any of ($a_*)
 
}