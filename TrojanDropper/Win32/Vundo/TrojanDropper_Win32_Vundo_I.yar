
rule TrojanDropper_Win32_Vundo_I{
	meta:
		description = "TrojanDropper:Win32/Vundo.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 43 4c 53 49 44 5c 7b 35 30 44 35 31 30 37 41 2d 44 32 37 38 2d 34 38 37 31 2d 38 39 38 39 2d 46 34 43 45 41 41 46 35 39 43 46 43 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //01 00  CLASSES_ROOT\CLSID\{50D5107A-D278-4871-8989-F4CEAAF59CFC}\InProcServer32
		$a_01_1 = {6d 73 6a 65 74 35 31 2e 64 6c 6c } //01 00  msjet51.dll
		$a_01_2 = {66 c7 85 d8 fe ff ff d4 07 66 c7 85 da fe ff ff 08 00 66 c7 85 dc fe ff ff 03 00 66 c7 85 de fe ff ff 12 00 66 c7 85 e0 fe ff ff 0d 00 66 c7 85 e2 fe ff ff 00 00 66 c7 85 e4 fe ff ff 00 00 66 c7 85 e6 fe ff ff 00 00 8d 45 f8 50 8d 8d d8 fe ff ff 51 e8 } //00 00 
	condition:
		any of ($a_*)
 
}