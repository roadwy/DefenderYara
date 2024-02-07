
rule Trojan_Win32_Qakbot_EP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 90 01 01 33 18 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 33 c0 89 45 90 01 01 8b 45 90 01 01 83 c0 90 01 01 03 45 90 01 01 89 45 90 01 01 6a 00 e8 90 01 04 8b 5d 90 01 01 83 c3 90 01 01 03 5d 90 01 01 2b d8 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EP_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {6a 4c 2e 64 6c 6c } //01 00  jL.dll
		$a_01_2 = {41 75 70 47 47 59 56 4d 53 49 58 } //01 00  AupGGYVMSIX
		$a_01_3 = {42 55 51 4a 66 45 68 51 43 } //01 00  BUQJfEhQC
		$a_01_4 = {43 4b 4f 57 73 49 69 7a 52 64 6a } //01 00  CKOWsIizRdj
		$a_01_5 = {44 4d 48 6b 42 57 71 } //00 00  DMHkBWq
	condition:
		any of ($a_*)
 
}