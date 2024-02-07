
rule Worm_Win32_Ainslot_C{
	meta:
		description = "Worm:Win32/Ainslot.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 41 6e 74 69 44 65 62 75 67 } //01 00  mAntiDebug
		$a_01_1 = {6d 44 65 63 72 79 70 74 69 6f 6e } //01 00  mDecryption
		$a_01_2 = {6d 53 61 6e 64 62 6f 78 69 65 } //01 00  mSandboxie
		$a_01_3 = {6d 4b 69 6c 6c } //01 00  mKill
		$a_01_4 = {6d 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  mDownloader
		$a_01_5 = {6d 43 44 42 75 72 6e } //01 00  mCDBurn
		$a_01_6 = {6d 4d 73 6e } //01 00  mMsn
		$a_01_7 = {6d 55 73 62 } //02 00  mUsb
		$a_00_8 = {7c 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 6c 00 6e 00 6b 00 7c 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 6a 00 70 00 67 00 3b 00 2a 00 2e 00 62 00 6d 00 70 00 3b 00 2a 00 2e 00 67 00 69 00 66 00 7c 00 44 00 4c 00 4c 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 64 00 6c 00 6c 00 } //00 00  |Shortcut Files|*.lnk|Picture Files|*.jpg;*.bmp;*.gif|DLL Files|*.dll
	condition:
		any of ($a_*)
 
}