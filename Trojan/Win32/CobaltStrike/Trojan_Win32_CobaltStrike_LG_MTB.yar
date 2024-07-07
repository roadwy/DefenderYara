
rule Trojan_Win32_CobaltStrike_LG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b 8e 90 01 04 8b 46 90 01 01 31 04 11 83 c2 90 01 01 8b 86 90 01 04 05 90 01 04 03 86 90 01 04 09 86 90 01 04 8b 86 90 01 04 2b 86 90 01 04 31 46 70 8b 86 90 01 04 01 46 58 8b 86 90 01 04 2d 90 00 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}