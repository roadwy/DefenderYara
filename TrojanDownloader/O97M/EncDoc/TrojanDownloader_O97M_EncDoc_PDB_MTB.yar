
rule TrojanDownloader_O97M_EncDoc_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 43 3a 5c 5c 57 69 6e 44 4f 77 73 5c 5c 53 79 73 54 45 4d 33 32 5c 5c 43 4d 44 2e 65 78 65 20 2f 56 2f 44 2f 63 20 22 22 73 65 54 20 73 4b 6b 3d 73 63 72 69 70 74 26 26 73 65 54 20 70 78 3d 6d 73 68 74 61 } //1 Shell ("C:\\WinDOws\\SysTEM32\\CMD.exe /V/D/c ""seT sKk=script&&seT px=mshta
		$a_01_1 = {64 3d 27 68 48 73 76 54 74 50 3a 27 3b 47 48 73 76 65 74 4f 62 6a 48 73 76 65 63 74 28 63 2b 64 2b 27 26 26 73 45 54 20 55 46 38 3d 53 4b 55 5a 44 53 4b 55 5a 44 77 77 65 65 61 38 61 65 30 66 2e 75 73 6d 61 72 6f 62 2e 75 73 53 4b 55 5a 44 3f 32 53 4b 55 5a 44 27 29 3b 7d 63 61 74 63 68 28 65 29 7b 7d 63 6c 6f 73 65 28 29 } //1 d='hHsvTtP:';GHsvetObjHsvect(c+d+'&&sET UF8=SKUZDSKUZDwweea8ae0f.usmarob.usSKUZD?2SKUZD');}catch(e){}close()
		$a_01_2 = {53 4b 55 5a 44 3d 2f 25 22 22 3c 6e 75 6c 20 3e 20 25 58 4d 47 4b 25 2e 48 74 61 7c 43 4d 44 20 2f 63 20 21 70 78 21 20 21 58 4d 47 4b 21 2e 48 74 41 20 22 22 20 20 22 29 2c 20 76 62 48 69 64 64 65 6e } //1 SKUZD=/%""<nul > %XMGK%.Hta|CMD /c !px! !XMGK!.HtA ""  "), vbHidden
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}