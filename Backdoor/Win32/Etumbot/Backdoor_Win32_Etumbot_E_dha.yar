
rule Backdoor_Win32_Etumbot_E_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 43 45 4c 25 64 3d 25 64 2e 63 67 69 3f 25 73 00 } //1
		$a_01_1 = {2f 53 44 55 25 64 3d 25 64 2e 63 67 69 3f 25 73 00 } //1
		$a_01_2 = {c6 85 47 ff ff ff 25 c6 85 48 ff ff ff 64 c6 85 49 ff ff ff 2e c6 85 4a ff ff ff 63 c6 85 4b ff ff ff 67 c6 85 4c ff ff ff 69 c6 85 4d ff ff ff 3f c6 85 4e ff ff ff 25 c6 85 4f ff ff ff 73 } //1
		$a_01_3 = {c6 45 e8 20 c6 45 e9 65 c6 45 ea 72 c6 45 eb 72 c6 45 ec 6f c6 45 ed 72 c6 45 ee 5b } //1
		$a_01_4 = {c6 45 c4 62 c6 45 c5 36 c6 45 c6 34 c6 45 c7 5f c6 45 c8 6e c6 45 c9 74 c6 45 ca 6f c6 45 cb 70 } //1
		$a_01_5 = {c6 45 e6 77 c6 45 e7 72 c6 45 e8 6f c6 45 e9 74 c6 45 ea 65 c6 45 eb 28 c6 45 ec 25 c6 45 ed 64 c6 45 ee 29 c6 45 ef 2e } //1
		$a_01_6 = {66 c7 85 48 f1 ff ff 6f 00 66 c7 85 4a f1 ff ff 6e 00 66 c7 85 4c f1 ff ff 6c 00 66 c7 85 4e f1 ff ff 69 00 66 c7 85 50 f1 ff ff 6e 00 66 c7 85 52 f1 ff ff 65 00 } //1
		$a_01_7 = {c6 85 90 c7 ff ff 2b c6 85 91 c7 ff ff 4f c6 85 92 c7 ff ff 4b c6 85 93 c7 ff ff 20 c6 85 94 c7 ff ff 43 c6 85 95 c7 ff ff 45 c6 85 96 c7 ff ff 4c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}