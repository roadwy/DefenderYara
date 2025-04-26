
rule TrojanSpy_Win64_Hesperbot_A{
	meta:
		description = "TrojanSpy:Win64/Hesperbot.A,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 05 58 bd 00 00 48 8b d3 b9 0a 00 00 00 4c 2b c3 0f 1f 44 00 00 41 0f b6 04 10 48 ff c2 48 ff c9 88 42 ff 75 } //5
		$a_01_1 = {6b 65 79 6c 6f 67 5f 6d 6f 64 5f 78 36 34 2e 6d 6f 64 } //5 keylog_mod_x64.mod
		$a_01_2 = {5b 00 64 00 65 00 6c 00 5d 00 } //5 [del]
		$a_01_3 = {49 6e 73 74 61 6c 6c 44 61 74 65 } //3 InstallDate
		$a_01_4 = {44 69 67 69 74 61 6c 50 72 6f 64 75 63 74 49 64 } //3 DigitalProductId
		$a_01_5 = {4d 61 63 68 69 6e 65 47 75 69 64 } //3 MachineGuid
		$a_01_6 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 \Windows NT\CurrentVersion
		$a_01_7 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 \Microsoft\Cryptography
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=26
 
}