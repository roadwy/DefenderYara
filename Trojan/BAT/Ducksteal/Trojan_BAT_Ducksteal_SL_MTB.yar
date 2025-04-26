
rule Trojan_BAT_Ducksteal_SL_MTB{
	meta:
		description = "Trojan:BAT/Ducksteal.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 64 62 30 37 33 39 61 65 2d 38 65 31 39 2d 34 33 38 37 2d 38 36 32 37 2d 35 63 39 30 31 62 30 65 33 64 33 65 } //1 $db0739ae-8e19-4387-8627-5c901b0e3d3e
		$a_81_1 = {45 3a 5c 57 6f 72 6b 73 70 61 63 65 5c 50 72 6f 6a 65 63 74 73 5c 73 63 61 6e 63 6f 6f 6b 69 65 73 65 72 76 65 72 32 5c 54 6f 6f 6c 73 43 68 65 63 6b 43 6f 6f 6b 69 65 5c 43 55 6e 50 72 6f 74 65 63 74 44 61 74 61 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 63 75 6e 70 72 6f 74 65 63 74 64 61 74 61 2e 70 64 62 } //1 E:\Workspace\Projects\scancookieserver2\ToolsCheckCookie\CUnProtectData\obj\Release\cunprotectdata.pdb
		$a_81_2 = {63 75 6e 70 72 6f 74 65 63 74 64 61 74 61 2e 65 78 65 } //1 cunprotectdata.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}