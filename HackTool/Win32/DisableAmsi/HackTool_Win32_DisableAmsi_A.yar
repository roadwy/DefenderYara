
rule HackTool_Win32_DisableAmsi_A{
	meta:
		description = "HackTool:Win32/DisableAmsi.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {52 53 44 53 90 02 18 43 3a 5c 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 41 6d 73 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 6d 73 69 2e 70 64 62 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}