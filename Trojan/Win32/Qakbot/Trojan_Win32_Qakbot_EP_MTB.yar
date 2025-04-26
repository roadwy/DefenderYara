
rule Trojan_Win32_Qakbot_EP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ?? 33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 ?? 03 45 ?? 89 45 ?? 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 ?? 03 5d ?? 2b d8 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_EP_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {6a 4c 2e 64 6c 6c } //1 jL.dll
		$a_01_2 = {41 75 70 47 47 59 56 4d 53 49 58 } //1 AupGGYVMSIX
		$a_01_3 = {42 55 51 4a 66 45 68 51 43 } //1 BUQJfEhQC
		$a_01_4 = {43 4b 4f 57 73 49 69 7a 52 64 6a } //1 CKOWsIizRdj
		$a_01_5 = {44 4d 48 6b 42 57 71 } //1 DMHkBWq
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}