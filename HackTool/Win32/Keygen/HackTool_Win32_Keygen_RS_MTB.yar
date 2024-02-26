
rule HackTool_Win32_Keygen_RS_MTB{
	meta:
		description = "HackTool:Win32/Keygen.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 69 76 65 72 73 61 6c 20 4b 65 79 6d 61 6b 65 72 } //01 00  Universal Keymaker
		$a_01_1 = {6b 65 79 67 65 6e 2e 64 6c 6c } //01 00  keygen.dll
		$a_01_2 = {61 63 74 69 76 61 74 65 2e 61 64 6f 62 65 2e 63 6f 6d } //00 00  activate.adobe.com
	condition:
		any of ($a_*)
 
}