
rule Trojan_Win32_CobaltStrike_SI_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0c 32 b9 ?? ?? ?? ?? 8b 90 ?? ?? ?? ?? 83 c6 ?? 8b 78 ?? 2b ca 01 48 ?? 8b 88 ?? ?? ?? ?? 33 cf 81 c1 ?? ?? ?? ?? 33 ca 89 88 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}