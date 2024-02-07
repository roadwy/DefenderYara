
rule PWS_Win32_Seratin_A{
	meta:
		description = "PWS:Win32/Seratin.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 77 69 6e 61 63 63 65 73 74 6f 72 2e 64 61 74 } //01 00  C:\WINDOWS\winaccestor.dat
		$a_01_1 = {2f 3f 6f 6b 3d 31 26 61 70 70 5f 69 64 3d } //01 00  /?ok=1&app_id=
		$a_01_2 = {43 4c 53 49 44 5c 7b 41 38 39 38 31 44 42 39 2d 42 32 42 33 2d 34 37 44 37 2d 41 38 39 30 2d 39 43 39 44 39 46 34 43 35 35 35 32 7d } //01 00  CLSID\{A8981DB9-B2B3-47D7-A890-9C9D9F4C5552}
		$a_01_3 = {2f 3f 6d 6f 64 65 3d 75 70 64 61 74 65 } //01 00  /?mode=update
		$a_01_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 72 75 } //01 00  Accept-Language:ru
		$a_01_5 = {61 64 2d 63 6f 6e 66 69 67 } //00 00  ad-config
	condition:
		any of ($a_*)
 
}