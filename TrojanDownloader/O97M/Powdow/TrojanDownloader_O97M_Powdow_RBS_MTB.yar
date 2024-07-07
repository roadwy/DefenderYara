
rule TrojanDownloader_O97M_Powdow_RBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("Wscript.Shell")
		$a_01_2 = {53 68 65 6c 6c 2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 26 28 22 7b 30 7d 7b 31 7d 22 20 2d 66 20 27 49 45 27 2c 27 58 27 29 } //1 Shell.Run "powershell -windowstyle hidden &("{0}{1}" -f 'IE','X')
		$a_01_3 = {2e 49 6e 76 6f 6b 65 28 28 22 7b 31 7d 7b 38 7d 7b 35 7d 7b 37 7d 7b 36 7d 7b 30 7d 7b 33 7d 7b 32 7d 7b 34 7d 22 2d 66 27 65 6e 27 2c 27 68 74 27 2c 27 67 6f 2e 70 27 2c 27 69 75 73 2e 63 6f 6d 2f 6c 6f 27 2c 27 6e 67 27 2c 27 70 3a 27 2c 27 67 27 2c 27 2f 2f 76 65 67 61 27 2c 27 74 27 29 29 } //1 .Invoke(("{1}{8}{5}{7}{6}{0}{3}{2}{4}"-f'en','ht','go.p','ius.com/lo','ng','p:','g','//vega','t'))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}