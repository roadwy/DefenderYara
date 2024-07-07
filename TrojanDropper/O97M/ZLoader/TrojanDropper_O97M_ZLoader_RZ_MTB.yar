
rule TrojanDropper_O97M_ZLoader_RZ_MTB{
	meta:
		description = "TrojanDropper:O97M/ZLoader.RZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 47 6f 50 68 6f 74 6f 6e 69 63 73 5c 52 65 64 64 69 74 2e 76 62 73 } //1 CreateTextFile("c:\GoPhotonics\Reddit.vbs
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 22 52 65 67 73 76 72 33 32 2e 65 78 65 20 2d 73 20 63 3a 5c 47 6f 50 68 6f 74 6f 6e 69 63 73 5c 57 61 76 65 70 6c 61 74 65 2e 64 6c 6c } //1 CreateObject("WScript.shell").exec "Regsvr32.exe -s c:\GoPhotonics\Waveplate.dll
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 22 25 63 6f 6d 73 70 65 63 25 20 2f 63 20 73 74 61 72 74 20 2f 77 61 69 74 20 63 3a 5c 47 6f 50 68 6f 74 6f 6e 69 63 73 5c 52 65 64 64 69 74 2e 76 62 73 } //1 CreateObject("WScript.shell").exec "%comspec% /c start /wait c:\GoPhotonics\Reddit.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}