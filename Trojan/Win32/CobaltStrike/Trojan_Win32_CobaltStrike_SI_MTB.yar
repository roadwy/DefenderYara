
rule Trojan_Win32_CobaltStrike_SI_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 0c 32 b9 90 01 04 8b 90 90 01 04 83 c6 90 01 01 8b 78 90 01 01 2b ca 01 48 90 01 01 8b 88 90 01 04 33 cf 81 c1 90 01 04 33 ca 89 88 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}