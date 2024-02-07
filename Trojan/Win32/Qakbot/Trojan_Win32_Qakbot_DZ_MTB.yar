
rule Trojan_Win32_Qakbot_DZ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {58 34 2e 64 6c 6c } //01 00  X4.dll
		$a_01_2 = {41 6e 65 6d 4a 6c 4a 39 57 71 } //01 00  AnemJlJ9Wq
		$a_01_3 = {42 34 4f 68 57 35 36 4d 73 4b } //01 00  B4OhW56MsK
		$a_01_4 = {43 4b 30 75 30 75 33 73 37 32 7a } //01 00  CK0u0u3s72z
		$a_01_5 = {44 58 35 42 66 31 36 45 } //01 00  DX5Bf16E
		$a_01_6 = {41 35 2e 64 6c 6c } //01 00  A5.dll
		$a_01_7 = {41 51 4f 6c 77 35 6c 53 50 7a } //01 00  AQOlw5lSPz
		$a_01_8 = {42 5a 70 4c 46 78 55 4a 78 36 48 } //01 00  BZpLFxUJx6H
		$a_01_9 = {43 77 4b 47 6e 54 62 46 65 } //01 00  CwKGnTbFe
		$a_01_10 = {44 70 6a 41 76 64 44 44 54 62 } //00 00  DpjAvdDDTb
	condition:
		any of ($a_*)
 
}