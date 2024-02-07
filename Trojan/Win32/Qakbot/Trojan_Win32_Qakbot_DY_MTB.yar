
rule Trojan_Win32_Qakbot_DY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {76 36 2e 64 6c 6c } //01 00  v6.dll
		$a_01_2 = {41 72 4d 36 4b 49 65 62 46 70 } //01 00  ArM6KIebFp
		$a_01_3 = {42 75 77 51 39 72 30 50 49 69 42 } //01 00  BuwQ9r0PIiB
		$a_01_4 = {43 35 32 63 74 79 73 49 67 59 42 } //01 00  C52ctysIgYB
		$a_01_5 = {44 78 66 54 4d 41 4d 54 66 45 } //01 00  DxfTMAMTfE
		$a_01_6 = {30 6e 2e 64 6c 6c } //01 00  0n.dll
		$a_01_7 = {41 51 65 56 6b 4f 61 } //01 00  AQeVkOa
		$a_01_8 = {43 37 6d 31 78 58 78 6a 46 32 76 } //01 00  C7m1xXxjF2v
		$a_01_9 = {43 71 67 74 31 78 75 6f 4c 68 } //01 00  Cqgt1xuoLh
		$a_01_10 = {44 71 78 44 56 39 34 52 58 4d 6e } //00 00  DqxDV94RXMn
	condition:
		any of ($a_*)
 
}