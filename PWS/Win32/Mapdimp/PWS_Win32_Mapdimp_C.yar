
rule PWS_Win32_Mapdimp_C{
	meta:
		description = "PWS:Win32/Mapdimp.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00 } //01 00 
		$a_03_1 = {6a f4 ff 75 fc ff 15 90 01 04 3d 9c 10 01 00 75 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}