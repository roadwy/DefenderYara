
rule TrojanDownloader_Win32_Deyma_AU_MTB{
	meta:
		description = "TrojanDownloader:Win32/Deyma.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 6f 4e 4f 75 52 4c 54 45 4c 58 32 64 41 62 33 72 4a 77 63 55 33 32 66 62 33 68 5a 56 4f 34 53 75 51 70 35 64 4e 77 38 32 76 39 46 53 30 6a 34 4c 4e 54 30 50 48 51 31 4c 56 61 32 78 47 7a 37 4e 45 56 37 77 52 77 50 6d 44 70 4f 47 } //1 PRoNOuRLTELX2dAb3rJwcU32fb3hZVO4SuQp5dNw82v9FS0j4LNT0PHQ1LVa2xGz7NEV7wRwPmDpOG
		$a_01_1 = {45 4c 59 4e 4b 4c 46 4f 51 6b 37 43 48 4b 6f 76 41 55 3d 3d } //1 ELYNKLFOQk7CHKovAU==
		$a_01_2 = {50 78 4d 70 53 54 46 66 38 58 4b 3d } //1 PxMpSTFf8XK=
		$a_01_3 = {4d 53 59 55 4d 63 42 59 37 58 58 68 4a 54 63 70 35 4b 4e 6d 54 4f 33 6f 65 6c 3d 3d } //1 MSYUMcBY7XXhJTcp5KNmTO3oel==
		$a_01_4 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //1 Amadey\Release\Amadey.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}