
rule TrojanDownloader_Win32_Cypaux_C{
	meta:
		description = "TrojanDownloader:Win32/Cypaux.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 00 64 00 72 00 2f 00 6c 00 6f 00 61 00 64 00 4c 00 69 00 73 00 74 00 2e 00 70 00 68 00 70 00 3f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 } //1 ldr/loadList.php?version=
		$a_01_1 = {57 69 6e 64 6f 77 73 55 70 61 64 74 65 } //1 WindowsUpadte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}