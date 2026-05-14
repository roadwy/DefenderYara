
rule DoS_Win32_ThornWiper_B_dha{
	meta:
		description = "DoS:Win32/ThornWiper.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 61 7a 61 72 65 74 68 } //1 nazareth
		$a_01_1 = {6c 6e 6b 6d 75 69 69 6e 66 69 6e 66 5f 6c 6f 63 6b 69 63 6f 74 74 66 74 74 63 77 61 76 6d 69 64 6d 62 70 70 66 66 6f 6e 6f 74 66 } //1 lnkmuiinfinf_lockicottfttcwavmidmbppffonotf
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 65 3a 4f 4e 20 2f 76 3a 4f 46 46 20 2f 64 20 2f 63 } //1 cmd.exe /e:ON /v:OFF /d /c
		$a_01_3 = {5c 2e 5c 4e 55 4c 5c 63 6d 64 2e 65 78 65 } //1 \.\NUL\cmd.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}