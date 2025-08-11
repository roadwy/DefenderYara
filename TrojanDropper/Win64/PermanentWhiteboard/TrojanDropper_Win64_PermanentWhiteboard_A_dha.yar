
rule TrojanDropper_Win64_PermanentWhiteboard_A_dha{
	meta:
		description = "TrojanDropper:Win64/PermanentWhiteboard.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 72 6f 6e 65 45 58 45 48 69 6a 61 63 6b 69 6e 67 4c 6f 61 64 65 72 2e 64 6c 6c } //1 DroneEXEHijackingLoader.dll
		$a_43_1 = {bf 00 28 00 00 41 be ff 03 00 00 41 bc 00 24 00 00 0f b7 d1 41 8d 04 0f 66 41 3b c6 77 90 01 01 8b fa c1 e7 0a 81 ef 00 00 5f 03 90 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_43_1  & 1)*1) >=2
 
}