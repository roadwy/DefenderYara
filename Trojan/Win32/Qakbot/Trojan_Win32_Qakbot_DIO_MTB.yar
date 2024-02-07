
rule Trojan_Win32_Qakbot_DIO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 83 c2 04 31 01 8b 86 90 01 04 31 46 40 b8 90 01 04 2b 86 90 01 04 01 86 90 01 04 8b 46 48 2d 90 01 04 01 46 68 8b 86 90 01 04 01 46 74 b8 90 01 04 2b 46 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}