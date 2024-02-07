
rule Trojan_Win32_Qakbot_EK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 55 a8 03 55 ac 4a 2b d0 89 55 a4 } //02 00 
		$a_01_1 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {6a 6e 53 59 67 64 48 62 2e 64 6c 6c } //01 00  jnSYgdHb.dll
		$a_01_2 = {41 66 6d 71 56 53 43 } //01 00  AfmqVSC
		$a_01_3 = {42 33 67 74 71 78 45 65 6a } //01 00  B3gtqxEej
		$a_01_4 = {43 31 74 65 63 58 65 62 73 } //01 00  C1tecXebs
		$a_01_5 = {44 36 70 6e 38 4d 7a 41 } //01 00  D6pn8MzA
		$a_01_6 = {49 55 72 67 4c 50 51 72 2e 64 6c 6c } //01 00  IUrgLPQr.dll
		$a_01_7 = {42 78 68 6c 7a 70 41 59 } //01 00  BxhlzpAY
		$a_01_8 = {43 6a 58 4e 7a 79 34 6c 42 } //01 00  CjXNzy4lB
		$a_01_9 = {46 37 4d 49 6c 63 37 6b 4a 6e 6d } //01 00  F7MIlc7kJnm
		$a_01_10 = {4a 57 73 6c 37 59 69 56 57 } //00 00  JWsl7YiVW
	condition:
		any of ($a_*)
 
}