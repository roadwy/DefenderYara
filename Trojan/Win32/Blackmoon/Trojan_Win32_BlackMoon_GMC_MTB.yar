
rule Trojan_Win32_BlackMoon_GMC_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {04 41 00 db 04 41 00 b7 04 41 00 c3 04 41 00 cf 04 41 00 8b 44 24 08 85 c0 74 07 50 e8 32 39 00 00 59 c3 } //01 00 
		$a_80_1 = {43 3a 5c 54 45 4d 50 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //C:\TEMP\svchost.exe  00 00 
	condition:
		any of ($a_*)
 
}