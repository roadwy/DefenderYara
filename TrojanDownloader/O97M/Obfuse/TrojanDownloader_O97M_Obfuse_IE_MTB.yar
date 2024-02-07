
rule TrojanDownloader_O97M_Obfuse_IE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //01 00  .js"
		$a_03_1 = {2b 20 22 5c 22 20 2b 20 90 02 24 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } //01 00  = Environ("windir") + "\Temp"
		$a_01_3 = {6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  ll.Application")
		$a_01_4 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //01 00  .Controls(0).ControlTipText
		$a_01_5 = {2e 49 6e 76 6f 6b 65 56 65 72 62 20 28 } //01 00  .InvokeVerb (
		$a_01_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}