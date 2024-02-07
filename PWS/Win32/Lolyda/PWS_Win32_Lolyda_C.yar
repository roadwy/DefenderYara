
rule PWS_Win32_Lolyda_C{
	meta:
		description = "PWS:Win32/Lolyda.C,SIGNATURE_TYPE_PEHSTR_EXT,49 00 49 00 0c 00 00 0a 00 "
		
	strings :
		$a_80_0 = {00 4c 4f 41 44 45 52 00 4c 59 4c 4f 41 44 45 52 2e 45 58 45 00 4d 42 45 52 00 } //  0a 00 
		$a_00_1 = {00 22 25 73 22 00 30 34 33 30 } //0a 00  ∀猥"㐰〳
		$a_80_2 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //MZKERNEL32.DLL  0a 00 
		$a_00_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //0a 00  SizeofResource
		$a_00_4 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //0a 00  FindResourceA
		$a_00_5 = {52 74 6c 5a 65 72 6f 4d 65 6d 6f 72 79 } //0a 00  RtlZeroMemory
		$a_00_6 = {57 72 69 74 65 46 69 6c 65 } //01 00  WriteFile
		$a_80_7 = {4c 59 4d 41 4e 47 52 2e 44 4c 4c } //LYMANGR.DLL  01 00 
		$a_80_8 = {00 4d 48 4c 59 00 } //  01 00 
		$a_80_9 = {4d 53 44 45 47 33 32 2e 44 4c 4c } //MSDEG32.DLL  01 00 
		$a_80_10 = {52 45 47 4b 45 59 2e 48 49 56 } //REGKEY.HIV  03 00 
		$a_01_11 = {55 8b ec 81 c4 a4 fb ff ff eb 21 6a 00 6a 00 6a 00 6a 00 e8 0e 01 00 00 6a 00 6a 00 6a 00 6a 00 e8 01 01 00 00 56 57 e8 72 01 00 00 e8 bd fe ff ff 68 04 01 00 00 8d 85 b8 fc ff ff 50 6a 00 e8 18 01 00 00 68 00 02 00 00 8d 85 bc fd ff ff 50 e8 2b 01 00 00 68 00 30 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}