
rule Trojan_Win32_Qakbot_HA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 68 6e 6d 31 30 39 72 6f 30 38 2e 64 6c 6c } //1 whnm109ro08.dll
		$a_01_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //1 DrawThemeIcon
		$a_01_2 = {52 59 4a 64 77 38 34 35 35 64 7a 53 } //1 RYJdw8455dzS
		$a_01_3 = {46 64 46 41 39 42 37 4e } //1 FdFA9B7N
		$a_01_4 = {5a 67 59 54 30 74 34 69 } //1 ZgYT0t4i
		$a_01_5 = {43 77 6d 55 63 67 38 36 } //1 CwmUcg86
		$a_01_6 = {43 62 4e 42 30 } //1 CbNB0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}