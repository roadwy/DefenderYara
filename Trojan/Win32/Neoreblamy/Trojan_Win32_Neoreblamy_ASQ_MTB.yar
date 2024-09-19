
rule Trojan_Win32_Neoreblamy_ASQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {64 71 56 49 53 6e 71 53 70 50 72 59 43 51 45 42 55 77 4d 6d 43 64 6d 79 44 51 59 58 45 74 } //1 dqVISnqSpPrYCQEBUwMmCdmyDQYXEt
		$a_01_1 = {41 73 73 70 51 77 70 66 4c 61 65 6d 55 57 42 50 59 4d 70 76 4e 58 73 4e 75 6e 6c 44 46 41 } //1 AsspQwpfLaemUWBPYMpvNXsNunlDFA
		$a_01_2 = {41 67 75 46 77 6a 68 67 4f 75 6f 65 4c 4e 73 6b 6d 4f 68 49 46 73 42 79 56 64 78 58 44 67 76 64 69 47 } //1 AguFwjhgOuoeLNskmOhIFsByVdxXDgvdiG
		$a_01_3 = {71 71 6f 4a 75 43 64 61 6d 52 49 50 77 48 55 54 2e 64 6c 6c } //1 qqoJuCdamRIPwHUT.dll
		$a_01_4 = {73 67 62 6d 41 55 51 67 57 66 65 71 51 64 52 62 57 52 75 46 4c 6c 72 6d 62 } //1 sgbmAUQgWfeqQdRbWRuFLlrmb
		$a_01_5 = {69 6a 58 44 43 52 69 68 74 75 72 44 49 76 7a 4b 74 43 77 44 54 75 6f 75 6d 55 6b 68 56 69 } //1 ijXDCRihturDIvzKtCwDTuoumUkhVi
		$a_01_6 = {49 6b 4b 6f 4e 4b 58 65 62 56 75 73 79 7a 4f 6b 74 77 79 66 73 53 59 6c 76 4f 7a 58 69 68 6b 78 47 4f } //1 IkKoNKXebVusyzOktwyfsSYlvOzXihkxGO
		$a_01_7 = {6d 71 68 63 6a 6b 48 66 76 54 70 6b 77 51 51 76 73 49 7a 66 66 46 4a 50 6d 67 47 49 47 75 63 4d 73 47 68 71 66 4a 61 63 56 6d 69 52 6a 68 72 45 6a 62 4c } //1 mqhcjkHfvTpkwQQvsIzffFJPmgGIGucMsGhqfJacVmiRjhrEjbL
		$a_01_8 = {47 64 70 55 45 78 62 4e 45 52 58 7a 5a 51 42 4a 57 43 4d 6f 73 66 6d 65 47 49 6e 6b 61 4b } //1 GdpUExbNERXzZQBJWCMosfmeGInkaK
		$a_01_9 = {4b 68 78 41 77 77 41 58 4c 66 61 75 6c 41 6b 6d 69 6d 67 67 48 59 4a 5a 51 55 4c 44 65 57 79 43 68 45 } //1 KhxAwwAXLfaulAkmimggHYJZQULDeWyChE
		$a_01_10 = {71 73 69 6e 48 6f 65 6b 4f 61 42 56 58 6b 45 77 62 57 63 61 72 6f 50 54 53 4a 70 76 44 } //1 qsinHoekOaBVXkEwbWcaroPTSJpvD
		$a_01_11 = {75 47 74 78 6e 52 71 41 5a 57 74 6f 66 68 78 42 69 43 77 7a 58 47 4e 73 53 6e 5a 4a 73 53 79 6f } //1 uGtxnRqAZWtofhxBiCwzXGNsSnZJsSyo
		$a_01_12 = {77 66 49 6f 7a 58 57 67 48 54 55 7a 4e 63 6e 6b 70 6b 6c 66 54 62 6b 78 64 68 67 62 67 55 } //1 wfIozXWgHTUzNcnkpklfTbkxdhgbgU
		$a_01_13 = {71 51 57 4e 4a 61 56 6d 66 77 56 46 5a 57 75 74 71 73 4d 77 50 47 76 74 55 6b 79 66 } //1 qQWNJaVmfwVFZWutqsMwPGvtUkyf
		$a_01_14 = {4f 6d 74 71 51 54 52 73 53 52 4e 78 64 55 5a 65 4b 4d 64 75 4b 58 49 6d 53 7a 43 4d 63 6a 44 6d 72 66 } //1 OmtqQTRsSRNxdUZeKMduKXImSzCMcjDmrf
		$a_01_15 = {57 63 67 56 43 51 47 75 46 55 79 2e 64 6c 6c } //1 WcgVCQGuFUy.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}