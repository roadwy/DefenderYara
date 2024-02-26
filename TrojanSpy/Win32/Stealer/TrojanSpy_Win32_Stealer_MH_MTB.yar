
rule TrojanSpy_Win32_Stealer_MH_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 44 65 6c 65 74 65 } //01 00  SelfDelete
		$a_01_1 = {4f 76 65 72 77 72 69 74 65 4d 6f 64 65 } //01 00  OverwriteMode
		$a_01_2 = {67 69 64 63 6f 6e 3a 63 6d 64 20 2f 63 20 63 6d 64 20 3c 20 4c 61 73 63 69 61 2e 61 61 63 } //01 00  gidcon:cmd /c cmd < Lascia.aac
		$a_01_3 = {64 6c 6c 68 6f 73 74 2e 65 78 65 } //01 00  dllhost.exe
		$a_01_4 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_5 = {66 00 6f 00 72 00 63 00 65 00 6e 00 6f 00 77 00 61 00 69 00 74 00 } //01 00  forcenowait
		$a_01_6 = {54 00 45 00 4d 00 50 00 5c 00 37 00 5a 00 69 00 70 00 53 00 66 00 78 00 2e 00 30 00 30 00 30 00 } //00 00  TEMP\7ZipSfx.000
	condition:
		any of ($a_*)
 
}