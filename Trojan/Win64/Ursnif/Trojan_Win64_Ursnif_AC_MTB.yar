
rule Trojan_Win64_Ursnif_AC_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {47 72 61 62 62 69 6e 67 20 49 45 20 63 6f 6f 6b 69 65 73 } //03 00  Grabbing IE cookies
		$a_81_1 = {67 72 63 6f 6f 6b 36 34 2e 70 64 62 } //03 00  grcook64.pdb
		$a_81_2 = {4e 53 53 5f 53 68 75 74 64 6f 77 6e } //03 00  NSS_Shutdown
		$a_81_3 = {42 43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //03 00  BCryptDestroyKey
		$a_81_4 = {50 4b 31 31 5f 46 72 65 65 53 6c 6f 74 } //03 00  PK11_FreeSlot
		$a_81_5 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //03 00  PK11SDR_Decrypt
		$a_81_6 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //03 00  cookies.sqlite
		$a_81_7 = {2a 2e 74 78 74 } //00 00  *.txt
	condition:
		any of ($a_*)
 
}