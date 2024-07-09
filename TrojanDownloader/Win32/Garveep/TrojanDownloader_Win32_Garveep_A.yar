
rule TrojanDownloader_Win32_Garveep_A{
	meta:
		description = "TrojanDownloader:Win32/Garveep.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 7e 07 80 30 ?? 40 49 75 f9 } //1
		$a_03_1 = {3d 97 01 00 00 0f 84 ?? ?? ?? ?? 68 00 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}