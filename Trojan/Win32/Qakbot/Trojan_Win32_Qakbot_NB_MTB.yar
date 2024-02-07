
rule Trojan_Win32_Qakbot_NB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {48 64 42 4e 4f 38 49 37 67 34 47 2e 64 6c 6c } //03 00  HdBNO8I7g4G.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //03 00  DllRegisterServer
		$a_81_2 = {44 74 6d 71 75 52 6f 44 6b } //03 00  DtmquRoDk
		$a_81_3 = {77 4f 74 6e 72 } //03 00  wOtnr
		$a_81_4 = {79 4a 74 75 48 45 74 65 69 } //03 00  yJtuHEtei
		$a_81_5 = {4d 6c 76 42 70 72 63 50 65 49 55 45 4e 58 48 41 61 68 4c 38 68 72 66 39 46 79 54 37 65 63 56 7a 44 36 37 6b 6a 75 36 49 4d 36 44 6e 42 4c 42 32 36 6f 63 4f 31 5a 78 52 72 7a 68 6a } //03 00  MlvBprcPeIUENXHAahL8hrf9FyT7ecVzD67kju6IM6DnBLB26ocO1ZxRrzhj
		$a_81_6 = {53 63 72 69 70 74 47 65 74 47 6c 79 70 68 41 42 43 57 69 64 74 68 } //00 00  ScriptGetGlyphABCWidth
	condition:
		any of ($a_*)
 
}