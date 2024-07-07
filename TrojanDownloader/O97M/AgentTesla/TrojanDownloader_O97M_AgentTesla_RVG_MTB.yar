
rule TrojanDownloader_O97M_AgentTesla_RVG_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 6d 69 63 29 73 65 74 77 30 62 6e 75 37 65 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 77 6e 65 29 64 69 6d 64 6f 77 61 73 73 74 72 69 6e 67 64 6f 77 3d 22 64 6f 77 6e 6c 6f 61 64 64 61 74 61 22 75 3d 22 68 74 74 70 3a 2f 2f 74 6f 70 76 61 6c 75 61 74 69 6f 6e 66 69 72 6d 73 2e 63 6f 6d 2f 74 65 6c 65 78 63 6f 70 79 2e 70 6e 67 22 6e 3d 22 74 65 6c 65 78 63 6f 70 79 2e 70 6e 67 22 64 69 6d 61 73 79 6e 63 61 73 73 74 72 69 6e 67 61 73 79 6e 63 3d 22 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 61 73 79 6e 63 22 67 66 78 31 37 6c 6f 61 2e 6f 70 65 6e } //1 createobject(mic)setw0bnu7e=createobject(wne)dimdowasstringdow="downloaddata"u="http://topvaluationfirms.com/telexcopy.png"n="telexcopy.png"dimasyncasstringasync="downloadfileasync"gfx17loa.open
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_AgentTesla_RVG_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 61 6c 63 20 2b 20 22 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 90 02 1e 22 22 22 0d 0a 6b 61 6f 73 64 6b 71 6f 77 6b 64 6f 6b 2e 53 65 74 53 74 72 69 6e 67 56 61 6c 75 65 20 70 6f 6c 6f 6f 6f 6f 64 2c 20 6b 64 6b 61 73 6b 6c 6c 6c 6c 2c 90 00 } //1
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 6d 61 6d 61 6d 6d 61 6b 64 6b 64 20 26 20 22 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 53 74 64 52 65 67 50 72 6f 76 22 29 } //1 GetObject("winmgmts:\\" & mamammakdkd & "\root\default:StdRegProv")
		$a_01_2 = {70 6f 6c 6f 6f 6f 6f 64 20 3d 20 26 48 38 30 30 30 30 30 30 31 } //1 polooood = &H80000001
		$a_01_3 = {63 61 6c 63 20 3d 20 78 20 2b 20 6d 20 2b 20 72 20 2b 20 70 20 2b 20 74 75 20 2b 20 68 61 20 2b 20 63 75 6c 69 6b } //1 calc = x + m + r + p + tu + ha + culik
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}