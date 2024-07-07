
rule Trojan_Win32_Qakbot_HK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {46 55 48 4a 4d 6e 39 30 } //1 FUHJMn90
		$a_01_2 = {50 44 42 46 52 30 31 37 33 52 } //1 PDBFR0173R
		$a_01_3 = {55 72 63 63 42 37 30 50 } //1 UrccB70P
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}