
rule Trojan_Win32_SusRundll_ABC_MTB{
	meta:
		description = "Trojan:Win32/SusRundll.ABC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 00 55 00 4e 00 44 00 4c 00 4c 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 RUNDLL32.EXE
		$a_00_1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 53 00 65 00 72 00 76 00 65 00 4d 00 61 00 70 00 73 00 5c 00 44 00 78 00 73 00 61 00 62 00 6c 00 65 00 4f 00 6f 00 61 00 64 00 5c 00 4d 00 42 00 41 00 4d 00 52 00 77 00 73 00 64 00 65 00 68 00 65 00 62 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 \AppData\Local\ServeMaps\DxsableOoad\MBAMRwsdehebl.dll
		$a_00_2 = {53 00 6f 00 66 00 69 00 75 00 4d 00 4d 00 7a 00 63 00 71 00 6c 00 48 00 69 00 67 00 61 00 6e 00 71 00 } //1 SofiuMMzcqlHiganq
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}