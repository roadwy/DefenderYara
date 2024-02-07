
rule TrojanDownloader_O97M_Maluco_KSH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Maluco.KSH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {28 74 69 6c 70 53 2e 75 74 24 3d 6d 6a 24 3b 74 78 65 74 24 20 6e 69 6f 6a 2d 3d 75 74 24 3b 29 74 78 65 74 24 28 65 73 72 65 76 65 52 3a 3a 5d 79 61 72 72 41 5b 3b 29 28 79 61 72 72 41 72 61 68 43 6f 54 } //01 00  (tilpS.ut$=mj$;txet$ nioj-=ut$;)txet$(esreveR::]yarrA[;)(yarrArahCoT
		$a_00_1 = {64 6e 61 6d 6d 6f 63 2d 20 6e 65 64 64 69 68 20 65 6c 79 74 53 77 6f 64 6e 69 57 2d 20 6c 6c 65 68 73 72 65 77 6f 50 20 6e 69 6d 2f 20 74 72 61 74 73 20 63 2f 20 44 4d 43 } //00 00  dnammoc- neddih elytSwodniW- llehsrewoP nim/ trats c/ DMC
	condition:
		any of ($a_*)
 
}