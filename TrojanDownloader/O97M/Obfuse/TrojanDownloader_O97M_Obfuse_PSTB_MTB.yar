
rule TrojanDownloader_O97M_Obfuse_PSTB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PSTB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 66 74 28 70 70 74 4e 61 6d 65 2c 20 49 6e 53 74 72 28 70 70 74 4e 61 6d 65 2c 22 2e 22 29 29 20 26 20 22 70 64 66 22 } //1 = Left(pptName, InStr(pptName,".")) & "pdf"
		$a_01_1 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 } //1 = "WSCript.shell"
		$a_01_2 = {2e 52 75 6e 28 64 65 72 79 6b 65 71 62 71 6a 72 6d 6f 70 61 78 6d 6d 76 70 6a 7a 69 6b 65 2c 20 67 64 77 6f 61 73 64 6d 6a 66 73 7a 29 } //1 .Run(derykeqbqjrmopaxmmvpjzike, gdwoasdmjfsz)
		$a_01_3 = {49 41 63 51 42 42 41 45 67 41 61 77 42 42 41 47 45 41 5a 77 42 43 41 44 4d 41 51 51 42 49 41 47 73 41 51 51 42 4a 41 45 45 41 51 51 42 76 41 45 45 41 51 77 42 42 41 45 45 41 53 67 42 42 41 45 49 41 62 67 42 42 41 45 67 } //1 IAcQBBAEgAawBBAGEAZwBCADMAQQBIAGsAQQBJAEEAQQBvAEEAQwBBAEEASgBBAEIAbgBBAEg
		$a_01_4 = {49 41 4d 67 42 42 41 45 63 41 57 51 42 42 41 47 49 41 5a 77 42 43 41 47 38 41 51 51 42 48 41 48 63 41 51 51 42 6a 41 45 45 41 51 67 42 7a 41 45 45 41 53 41 42 42 41 45 45 41 57 67 42 52 41 45 49 41 64 77 42 42 41 45 63 41 4f 41 42 } //1 IAMgBBAEcAWQBBAGIAZwBCAG8AQQBHAHcAQQBjAEEAQgBzAEEASABBAEEAWgBRAEIAdwBBAEcAOAB
		$a_01_5 = {49 41 61 77 42 42 41 45 67 41 59 77 42 42 41 47 45 41 5a 77 42 43 41 47 30 41 51 51 42 48 41 44 41 41 51 51 42 6a 41 48 63 41 51 67 42 78 41 45 45 41 53 41 42 72 41 45 45 41 59 51 42 6e 41 45 49 41 4d 77 42 42 41 45 67 41 61 77 42 42 41 45 6b 41 51 51 42 42 41 47 34 41 51 51 42 } //1 IAawBBAEgAYwBBAGEAZwBCAG0AQQBHADAAQQBjAHcAQgBxAEEASABrAEEAYQBnAEIAMwBBAEgAawBBAEkAQQBBAG4AQQB
		$a_01_6 = {53 77 42 42 41 45 67 41 55 51 42 42 41 47 49 41 64 77 42 43 41 47 73 41 51 51 42 49 41 47 4d 41 51 51 42 68 41 47 63 41 51 67 42 74 41 45 45 41 52 77 41 77 41 45 45 41 59 77 42 33 41 45 49 41 63 51 42 42 41 45 67 41 61 77 42 42 41 47 45 } //1 SwBBAEgAUQBBAGIAdwBCAGsAQQBIAGMAQQBhAGcAQgBtAEEARwAwAEEAYwB3AEIAcQBBAEgAawBBAGE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}