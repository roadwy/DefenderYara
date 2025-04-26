
rule Trojan_Win32_ClipBanker_RDB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 75 6e 70 75 6e } //1 punpun
		$a_01_1 = {41 64 64 55 73 65 72 3a 64 69 65 67 6f 37 37 37 30 } //1 AddUser:diego7770
		$a_01_2 = {62 00 64 00 33 00 34 00 68 00 65 00 77 00 66 00 } //1 bd34hewf
		$a_01_3 = {37 39 2e 31 33 37 2e 31 39 36 2e 31 32 31 } //1 79.137.196.121
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}