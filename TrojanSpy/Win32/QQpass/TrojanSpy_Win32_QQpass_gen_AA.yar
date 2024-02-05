
rule TrojanSpy_Win32_QQpass_gen_AA{
	meta:
		description = "TrojanSpy:Win32/QQpass.gen!AA,SIGNATURE_TYPE_PEHSTR,28 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 65 67 69 73 74 65 72 61 74 69 6f 6e 20 45 72 72 6f 72 21 00 00 00 00 35 35 36 72 74 72 64 68 } //0a 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00 
		$a_01_2 = {35 35 36 72 74 72 64 68 } //0a 00 
		$a_01_3 = {ff ff ff ff 02 00 00 00 6d 6d 00 00 ff ff ff ff 03 00 00 00 64 6c 6c 00 53 74 61 72 74 48 6f 6f 6b 00 00 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}