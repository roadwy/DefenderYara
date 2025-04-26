
rule TrojanSpy_Win32_Hesperbot_B{
	meta:
		description = "TrojanSpy:Win32/Hesperbot.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 \Windows NT\CurrentVersion
		$a_01_1 = {25 5f 48 45 53 50 5f 42 4f 54 5f 49 44 5f 25 } //1 %_HESP_BOT_ID_%
		$a_01_2 = {24 5f 48 45 53 50 5f 52 45 51 5f 54 59 50 45 5f 24 } //1 $_HESP_REQ_TYPE_$
		$a_01_3 = {53 00 3a 00 28 00 4d 00 4c 00 3b 00 3b 00 4e 00 52 00 4e 00 57 00 4e 00 58 00 3b 00 3b 00 3b 00 4c 00 57 00 29 00 } //1 S:(ML;;NRNWNX;;;LW)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}