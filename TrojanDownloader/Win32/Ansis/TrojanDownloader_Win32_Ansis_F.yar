
rule TrojanDownloader_Win32_Ansis_F{
	meta:
		description = "TrojanDownloader:Win32/Ansis.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 fd 9a 80 5c 73 69 2e 65 78 65 22 20 fd a1 80 20 2f 70 69 64 3d 36 36 00 6f 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}