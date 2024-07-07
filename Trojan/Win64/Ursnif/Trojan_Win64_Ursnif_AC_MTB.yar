
rule Trojan_Win64_Ursnif_AC_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 72 61 62 62 69 6e 67 20 49 45 20 63 6f 6f 6b 69 65 73 } //3 Grabbing IE cookies
		$a_81_1 = {67 72 63 6f 6f 6b 36 34 2e 70 64 62 } //3 grcook64.pdb
		$a_81_2 = {4e 53 53 5f 53 68 75 74 64 6f 77 6e } //3 NSS_Shutdown
		$a_81_3 = {42 43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //3 BCryptDestroyKey
		$a_81_4 = {50 4b 31 31 5f 46 72 65 65 53 6c 6f 74 } //3 PK11_FreeSlot
		$a_81_5 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //3 PK11SDR_Decrypt
		$a_81_6 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //3 cookies.sqlite
		$a_81_7 = {2a 2e 74 78 74 } //3 *.txt
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3) >=24
 
}