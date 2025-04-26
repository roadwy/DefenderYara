
rule TrojanDownloader_O97M_Donoff_PA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 63 6d 64 2e 65 78 65 20 2f 76 3a 4f 4e 20 2f 63 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 73 65 74 } //1 Shell "cmd.exe /v:ON /c" + Chr(34) + "set
		$a_03_1 = {22 20 26 26 20 25 74 6d 70 25 2f [0-10] 2e 65 78 65 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}