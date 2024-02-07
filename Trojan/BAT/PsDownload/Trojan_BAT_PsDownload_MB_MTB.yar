
rule Trojan_BAT_PsDownload_MB_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 65 00 6e 00 63 00 20 00 55 00 77 00 42 00 30 00 41 00 45 00 45 00 41 00 63 00 67 00 42 00 30 00 41 00 43 00 30 00 41 00 55 00 77 00 42 00 73 00 41 00 45 00 } //01 00  -enc UwB0AEEAcgB0AC0AUwBsAE
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_3 = {3a 00 2f 00 2f 00 32 00 34 00 68 00 72 00 73 00 74 00 72 00 61 00 63 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 } //01 00  ://24hrstrack.com/loader/
		$a_01_4 = {43 6f 6d 70 75 74 65 42 72 6f 61 64 63 61 73 74 65 72 } //01 00  ComputeBroadcaster
		$a_01_5 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}