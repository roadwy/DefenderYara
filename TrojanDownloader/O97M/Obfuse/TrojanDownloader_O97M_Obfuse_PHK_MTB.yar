
rule TrojanDownloader_O97M_Obfuse_PHK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 41 42 54 41 48 6b 41 63 77 42 30 41 47 55 41 62 51 41 75 41 45 34 41 5a 51 42 30 41 43 34 41 56 77 42 6c 41 47 49 41 51 77 42 73 41 47 6b 41 5a 51 42 75 41 48 51 41 4b 51 41 75 41 45 51 41 62 77 42 33 41 47 34 41 62 41 42 76 41 47 45 41 5a 41 42 47 41 47 6b 41 62 41 42 } //1 IABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbAB
		$a_01_1 = {6c 41 43 67 41 49 67 42 6f 41 48 51 41 64 41 42 77 41 44 6f 41 4c 77 41 76 41 44 45 41 4d 77 41 75 41 44 6b 41 4d 67 41 75 41 44 45 41 4d 41 41 77 41 43 34 41 4d 67 41 77 41 44 67 41 4c 77 42 30 41 47 38 41 61 77 42 7a 41 43 38 41 59 51 42 31 41 47 51 41 61 51 42 76 41 43 34 41 5a 51 42 34 41 47 55 41 } //1 lACgAIgBoAHQAdABwADoALwAvADEAMwAuADkAMgAuADEAMAAwAC4AMgAwADgALwB0AG8AawBzAC8AYQB1AGQAaQBvAC4AZQB4AGUA
		$a_01_2 = {49 67 41 73 41 43 49 41 4a 41 42 6c 41 47 34 41 64 67 41 36 41 45 45 41 55 41 42 51 41 45 51 41 51 51 42 55 41 45 45 41 58 41 41 6b 41 46 41 41 63 67 42 76 41 47 4d 41 54 67 42 68 41 47 30 41 5a 51 41 69 41 43 6b 41 4f 77 42 54 41 48 51 41 59 51 42 79 41 48 51 41 4c 51 42 51 41 48 49 41 62 77 42 6a 41 47 55 41 63 77 42 7a 41 43 41 41 4b 41 41 69 41 43 51 41 5a 51 42 75 41 48 59 41 4f 67 42 42 41 46 41 41 55 41 42 45 41 45 45 41 56 41 42 42 41 46 77 41 4a 41 42 51 41 48 49 41 62 77 42 6a 41 45 34 41 59 51 42 74 41 47 55 41 49 67 41 70 41 41 3d 3d } //1 IgAsACIAJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAAkAFAAcgBvAGMATgBhAG0AZQAiACkAOwBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAKAAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}