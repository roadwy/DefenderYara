
rule Trojan_Win32_Farfli_CS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 69 73 53 72 76 2e 65 78 65 } //01 00  NisSrv.exe
		$a_01_1 = {25 73 5c 25 73 2e 65 78 65 } //01 00  %s\%s.exe
		$a_01_2 = {55 6e 54 68 72 65 61 74 2e 65 78 65 } //01 00  UnThreat.exe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_4 = {61 64 2d 77 61 74 63 68 2e 65 78 65 } //01 00  ad-watch.exe
		$a_01_5 = {61 76 63 65 6e 74 65 72 2e 65 78 65 } //01 00  avcenter.exe
		$a_01_6 = {6b 6e 73 64 74 72 61 79 2e 65 78 65 } //00 00  knsdtray.exe
	condition:
		any of ($a_*)
 
}