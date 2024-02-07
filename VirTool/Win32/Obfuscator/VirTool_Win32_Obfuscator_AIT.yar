
rule VirTool_Win32_Obfuscator_AIT{
	meta:
		description = "VirTool:Win32/Obfuscator.AIT,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 64 00 75 00 73 00 72 00 77 00 65 00 71 00 72 00 6a 00 74 00 72 00 61 00 5c 00 5a 00 6e 00 67 00 66 00 7a 00 6b 00 4c 00 5c 00 45 00 48 00 62 00 75 00 5c 00 70 00 61 00 50 00 70 00 78 00 68 00 6b 00 5c 00 69 00 78 00 51 00 78 00 70 00 79 00 75 00 70 00 61 00 5c 00 6a 00 72 00 6e 00 6e 00 79 00 } //01 00  C:\dusrweqrjtra\ZngfzkL\EHbu\paPpxhk\ixQxpyupa\jrnny
		$a_01_1 = {63 00 3a 00 5c 00 74 00 72 00 62 00 63 00 6c 00 5c 00 73 00 6e 00 70 00 68 00 4a 00 6b 00 5c 00 75 00 76 00 73 00 70 00 51 00 45 00 56 00 6e 00 5c 00 6a 00 72 00 72 00 42 00 69 00 4b 00 } //01 00  c:\trbcl\snphJk\uvspQEVn\jrrBiK
		$a_01_2 = {43 00 3a 00 5c 00 54 00 74 00 64 00 63 00 73 00 5c 00 6d 00 62 00 65 00 7a 00 43 00 74 00 6d 00 5c 00 42 00 72 00 6a 00 69 00 62 00 6a 00 77 00 6e 00 5c 00 4d 00 62 00 70 00 7a 00 69 00 70 00 5c 00 6d 00 6b 00 57 00 73 00 4b 00 2e 00 73 00 68 00 76 00 } //00 00  C:\Ttdcs\mbezCtm\Brjibjwn\Mbpzip\mkWsK.shv
	condition:
		any of ($a_*)
 
}