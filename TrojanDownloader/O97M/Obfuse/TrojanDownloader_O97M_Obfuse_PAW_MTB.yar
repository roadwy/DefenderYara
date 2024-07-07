
rule TrojanDownloader_O97M_Obfuse_PAW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 52 61 6e 73 6f 6d 77 61 72 65 20 77 61 73 20 63 72 65 61 74 65 64 20 75 73 69 6e 67 20 4e 52 4d 57 } //1 This Ransomware was created using NRMW
		$a_01_1 = {63 6f 64 65 20 62 79 20 4e 65 63 72 6f 6e 6f 6d 69 6b 6f 6e 2f 5b 44 30 30 4d 52 69 64 65 72 7a 5d } //1 code by Necronomikon/[D00MRiderz]
		$a_01_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 22 53 59 53 44 49 52 22 22 29 20 26 20 22 22 5c 66 74 70 2e 65 78 65 20 2d 73 3a 63 3a 5c 6e 65 63 2e 66 74 70 22 22 2c 20 76 62 48 69 64 65 } //1 Shell Environ(""SYSDIR"") & ""\ftp.exe -s:c:\nec.ftp"", vbHide
		$a_01_3 = {53 68 65 6c 6c 20 22 22 63 3a 5c 69 6e 66 6f 73 34 75 2e 74 78 74 } //1 Shell ""c:\infos4u.txt
		$a_03_4 = {53 68 65 6c 6c 20 22 22 63 3a 5c 90 02 10 2e 73 63 72 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}