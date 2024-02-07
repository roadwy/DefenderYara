
rule Trojan_Win32_Qakbot_DS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {69 45 6c 39 2e 64 6c 6c } //01 00  iEl9.dll
		$a_01_2 = {42 77 48 62 41 36 69 47 4c 70 79 } //01 00  BwHbA6iGLpy
		$a_01_3 = {44 41 49 62 50 53 36 78 } //01 00  DAIbPS6x
		$a_01_4 = {44 4c 59 77 42 45 39 4d 50 38 75 } //01 00  DLYwBE9MP8u
		$a_01_5 = {44 53 4f 76 66 53 6f 69 54 } //01 00  DSOvfSoiT
		$a_01_6 = {73 79 4d 6f 2e 64 6c 6c } //01 00  syMo.dll
		$a_01_7 = {43 39 67 79 54 71 52 57 42 38 } //01 00  C9gyTqRWB8
		$a_01_8 = {43 6e 75 33 50 44 31 62 76 } //01 00  Cnu3PD1bv
		$a_01_9 = {43 73 65 61 76 73 56 6b 36 49 5a } //01 00  CseavsVk6IZ
		$a_01_10 = {44 78 32 61 53 42 73 51 45 38 79 } //00 00  Dx2aSBsQE8y
	condition:
		any of ($a_*)
 
}