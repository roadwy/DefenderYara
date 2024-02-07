
rule VirTool_Win32_VBInject_FK{
	meta:
		description = "VirTool:Win32/VBInject.FK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 45 00 4d 00 4f 00 4e 00 5c 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00  \DEMON\Malware Production
		$a_01_1 = {53 00 68 00 61 00 72 00 6b 00 69 00 5c 00 53 00 68 00 61 00 72 00 6b 00 69 00 20 00 43 00 72 00 69 00 70 00 74 00 65 00 72 00 5c 00 44 00 45 00 4d 00 4f 00 4e 00 2e 00 } //02 00  Sharki\Sharki Cripter\DEMON.
		$a_03_2 = {50 51 ff d7 8b d0 8d 4d e0 ff d6 50 68 90 01 04 ff d7 8b d0 8d 4d dc ff d6 50 6a 01 6a ff 6a 20 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}