
rule Ransom_Win32_Xiaoba_YAC_MTB{
	meta:
		description = "Ransom:Win32/Xiaoba.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 41 50 49 2e 53 70 65 61 6b } //1 SAPI.Speak
		$a_01_1 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_2 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 74 74 65 6e 74 69 6f 6e 21 } //1 Attention! Attention!
		$a_01_3 = {48 45 4c 50 5f 53 4f 53 } //1 HELP_SOS
		$a_01_4 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 } //1 vssadmin delete shadow
		$a_01_5 = {58 49 41 4f 42 41 20 32 2e 30 20 52 61 6e 73 6f 6d 77 61 72 65 } //10 XIAOBA 2.0 Ransomware
		$a_01_6 = {73 65 74 65 6c 61 68 20 6d 65 6e 79 65 6c 65 73 61 69 6b 61 6e 20 74 72 61 6e 73 61 6b 73 69 } //1 setelah menyelesaikan transaksi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1) >=16
 
}