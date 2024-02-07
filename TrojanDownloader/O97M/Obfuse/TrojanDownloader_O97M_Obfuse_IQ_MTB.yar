
rule TrojanDownloader_O97M_Obfuse_IQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //01 00  .js"
		$a_01_1 = {22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 } //01 00  "new:13709620-C279-11CE-A49E-444553540000"
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } //01 00  = Environ("windir") + "\Temp"
		$a_01_3 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 } //01 00  .Controls(0)
		$a_03_4 = {4f 70 65 6e 20 90 02 15 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_01_5 = {2e 43 61 70 74 69 6f 6e } //00 00  .Caption
	condition:
		any of ($a_*)
 
}