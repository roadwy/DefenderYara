
rule TrojanDownloader_O97M_Encdoc_G_MSR{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 45 78 45 20 20 2f 63 20 50 4f 77 45 72 53 68 45 6c 6c 20 20 2d 45 58 20 62 59 50 61 53 73 20 2d 4e 6f 70 20 2d 57 20 31 } //1 cmd.ExE  /c POwErShEll  -EX bYPaSs -Nop -W 1
		$a_01_1 = {49 45 58 28 20 49 6e 56 6f 6b 65 2d 57 45 42 52 65 71 75 65 53 54 20 20 28 27 68 74 74 27 20 20 2b 20 27 70 73 3a 2f 2f 66 69 6c 65 2e 69 6f 2f 39 71 58 37 49 4a 68 69 50 43 27 20 20 2b 20 27 52 4b 27 } //1 IEX( InVoke-WEBRequeST  ('htt'  + 'ps://file.io/9qX7IJhiPC'  + 'RK'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}