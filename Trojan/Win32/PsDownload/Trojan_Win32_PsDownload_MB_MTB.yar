
rule Trojan_Win32_PsDownload_MB_MTB{
	meta:
		description = "Trojan:Win32/PsDownload.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 e1 07 c1 e1 03 0f ad ef d3 ed f6 c1 20 74 90 01 01 89 ef 66 31 3c 46 83 c0 01 89 c1 83 d2 00 83 f1 27 09 d1 75 90 00 } //01 00 
		$a_01_1 = {2e 74 6c 73 } //01 00 
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}