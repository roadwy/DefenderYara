
rule Trojan_Win32_BHO_CM{
	meta:
		description = "Trojan:Win32/BHO.CM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab aa 8d 85 e4 fe ff ff c7 04 24 90 01 04 50 89 5d f4 89 5d f0 e8 90 01 04 59 8d 85 e4 fe ff ff 59 68 90 01 04 68 04 01 00 00 50 e8 90 01 04 59 50 8d 85 e4 fe ff ff 50 e8 90 01 04 83 c4 10 8d 45 f8 50 8d 45 fc 50 53 68 3f 00 0f 00 90 00 } //01 00 
		$a_00_1 = {78 62 64 68 6f 32 2e 44 4c 4c } //01 00  xbdho2.DLL
		$a_00_2 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //01 00  CLSID\%s\InprocServer32
		$a_01_3 = {6b 65 79 00 63 68 61 6e 6e 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}