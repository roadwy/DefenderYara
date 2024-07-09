
rule TrojanDownloader_Win32_Harnig_C{
	meta:
		description = "TrojanDownloader:Win32/Harnig.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {46 66 8b 1a 66 83 c3 b2 66 89 1a 68 ba 1f 06 00 81 e8 ?? ?? ?? 00 71 01 46 5e 66 83 02 28 66 83 02 28 83 c2 01 42 53 c7 ?? ?? ?? ?? ?? 00 5e 39 f2 75 cd } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}