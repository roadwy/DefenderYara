
rule Trojan_Win32_Qbot_FQ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 69 39 45 77 61 52 36 47 68 4e } //1 Ai9EwaR6GhN
		$a_01_1 = {42 55 6f 65 72 54 65 } //1 BUoerTe
		$a_01_2 = {42 58 76 61 52 35 41 49 } //1 BXvaR5AI
		$a_01_3 = {42 6a 63 32 75 51 31 51 69 31 41 } //1 Bjc2uQ1Qi1A
		$a_01_4 = {42 75 50 30 42 54 58 } //1 BuP0BTX
		$a_01_5 = {42 76 4f 4b 68 4a 31 59 62 41 64 } //1 BvOKhJ1YbAd
		$a_01_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}