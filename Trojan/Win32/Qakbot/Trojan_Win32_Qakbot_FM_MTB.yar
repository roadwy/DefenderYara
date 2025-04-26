
rule Trojan_Win32_Qakbot_FM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {44 46 58 71 6d 31 38 38 39 } //1 DFXqm1889
		$a_01_3 = {4a 59 6e 56 38 55 } //1 JYnV8U
		$a_01_4 = {4e 6b 7a 4b 54 31 59 38 } //1 NkzKT1Y8
		$a_01_5 = {53 49 48 57 30 35 32 54 } //1 SIHW052T
		$a_01_6 = {54 7a 4b 38 36 36 30 31 } //1 TzK86601
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}