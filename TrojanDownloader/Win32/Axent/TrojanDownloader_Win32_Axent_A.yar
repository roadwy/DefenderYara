
rule TrojanDownloader_Win32_Axent_A{
	meta:
		description = "TrojanDownloader:Win32/Axent.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 78 6f 63 65 73 73 33 32 4e 65 78 74 } //05 00  Pxocess32Next
		$a_01_1 = {43 72 65 61 7a 65 50 72 6f 63 65 73 73 41 } //05 00  CreazeProcessA
		$a_01_2 = {75 53 6c 6d 6f 6e 2e 64 6c 6c } //05 00  uSlmon.dll
		$a_01_3 = {50 58 6f 63 65 73 73 33 32 46 69 72 73 74 } //02 00  PXocess32First
		$a_01_4 = {49 58 58 50 4c 4f 52 45 2e 45 58 45 } //02 00  IXXPLORE.EXE
		$a_01_5 = {78 73 78 73 6d 78 61 78 2e 45 58 45 } //02 00  xsxsmxax.EXE
		$a_01_6 = {2f 62 61 62 79 6e 6f 74 2f } //01 00  /babynot/
		$a_01_7 = {50 6f 69 26 65 72 28 } //02 00  Poi&er(
		$a_01_8 = {25 75 25 64 25 75 25 64 } //02 00  %u%d%u%d
		$a_01_9 = {25 73 25 73 25 73 3f 25 73 3d 25 73 } //00 00  %s%s%s?%s=%s
	condition:
		any of ($a_*)
 
}