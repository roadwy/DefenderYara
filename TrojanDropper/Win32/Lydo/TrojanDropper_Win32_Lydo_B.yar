
rule TrojanDropper_Win32_Lydo_B{
	meta:
		description = "TrojanDropper:Win32/Lydo.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {4c 59 4c 4f 41 44 45 52 2e 45 58 45 } //LYLOADER.EXE  01 00 
		$a_00_1 = {4c 00 59 00 4d 00 41 00 4e 00 47 00 52 00 2e 00 44 00 4c 00 4c 00 } //01 00  LYMANGR.DLL
		$a_00_2 = {4d 00 53 00 44 00 45 00 47 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 } //01 00  MSDEG32.DLL
		$a_00_3 = {52 00 45 00 47 00 4b 00 45 00 59 00 2e 00 48 00 49 00 56 00 } //01 00  REGKEY.HIV
		$a_00_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00  LoadResource
		$a_00_5 = {52 74 6c 5a 65 72 6f 4d 65 6d 6f 72 79 } //01 00  RtlZeroMemory
		$a_00_6 = {57 72 69 74 65 46 69 6c 65 } //0a 00  WriteFile
		$a_00_7 = {68 64 20 40 00 68 6b 20 40 00 ff 75 fc e8 b6 01 00 00 0b c0 74 73 89 45 f8 50 ff 75 fc e8 e2 01 00 00 89 45 f0 ff 75 f8 ff 75 fc e8 bc 01 00 00 0b c0 74 55 50 e8 b8 01 00 00 0b c0 74 4b 89 45 ec 6a 00 6a 20 6a 02 6a 00 6a 00 68 00 00 00 40 68 00 30 40 00 e8 5c 01 00 00 0b c0 74 2b 89 85 e4 fe ff ff 6a 00 8d 85 e0 fe ff ff 50 ff 75 f0 ff 75 ec ff b5 e4 fe ff ff e8 8c 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}