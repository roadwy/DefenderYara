
rule TrojanProxy_Win32_Dosenjo_C{
	meta:
		description = "TrojanProxy:Win32/Dosenjo.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {6a 6e 66 c7 45 ec 02 00 ff 15 90 01 04 83 65 f0 00 6a 10 5f 66 89 45 ee 57 8d 45 ec 50 53 90 00 } //03 00 
		$a_01_1 = {8b 4d 94 8a 4c 0d 98 30 08 ff 45 94 83 7d 94 20 72 04 83 65 94 00 40 80 38 00 75 e4 } //01 00 
		$a_01_2 = {3f 63 61 63 68 69 6e 67 44 65 6e 79 3d } //01 00  ?cachingDeny=
		$a_01_3 = {42 55 46 42 55 46 20 4e 4f 54 20 45 4e 43 } //01 00  BUFBUF NOT ENC
		$a_01_4 = {66 75 73 65 61 63 74 69 6f 6e 3d 73 69 74 65 73 65 61 72 63 68 2e 72 65 73 75 6c 74 73 } //02 00  fuseaction=sitesearch.results
		$a_01_5 = {3f 71 75 65 72 79 3d 00 2f 66 75 6c 6c 73 65 61 72 63 68 00 53 70 65 63 69 61 6c 3a 53 65 61 72 63 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}