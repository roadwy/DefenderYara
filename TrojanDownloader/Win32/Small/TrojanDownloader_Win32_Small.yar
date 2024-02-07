
rule TrojanDownloader_Win32_Small{
	meta:
		description = "TrojanDownloader:Win32/Small,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {25 73 5c 64 72 69 76 65 72 73 5c 70 63 69 68 64 64 32 2e 73 79 73 } //0a 00  %s\drivers\pcihdd2.sys
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 20 2e 74 78 74 90 00 } //0a 00 
		$a_00_2 = {5f 75 6e 69 6e 73 65 70 2e 62 61 74 } //01 00  _uninsep.bat
		$a_00_3 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f } //01 00  if exist "%s" goto
		$a_00_4 = {64 65 6c 20 22 25 73 22 } //01 00  del "%s"
		$a_00_5 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //01 00  ntoskrnl.exe
		$a_00_6 = {77 69 6e 65 78 65 63 } //01 00  winexec
		$a_00_7 = {45 3a 5c 4f 74 68 65 72 5c 53 65 63 45 64 69 74 5c 53 65 64 69 73 6b 5c 6f 62 6a 66 72 65 5f 77 32 4b 5f 78 38 36 5c 69 33 38 36 5c 53 65 64 69 73 6b 2e 70 64 62 } //00 00  E:\Other\SecEdit\Sedisk\objfre_w2K_x86\i386\Sedisk.pdb
	condition:
		any of ($a_*)
 
}