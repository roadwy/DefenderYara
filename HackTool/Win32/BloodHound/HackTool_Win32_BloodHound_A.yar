
rule HackTool_Win32_BloodHound_A{
	meta:
		description = "HackTool:Win32/BloodHound.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 6c 00 6f 00 6f 00 64 00 48 00 6f 00 75 00 6e 00 64 00 2e 00 62 00 69 00 6e 00 } //01 00  BloodHound.bin
		$a_01_1 = {73 61 6d 61 63 63 6f 75 6e 74 6e 61 6d 65 } //01 00  samaccountname
		$a_01_2 = {5f 00 42 00 6c 00 6f 00 6f 00 64 00 48 00 6f 00 75 00 6e 00 64 00 2e 00 7a 00 69 00 70 00 } //01 00  _BloodHound.zip
		$a_01_3 = {53 68 61 72 70 68 6f 75 6e 64 32 2e 4a 73 6f 6e 4f 62 6a 65 63 74 73 } //01 00  Sharphound2.JsonObjects
		$a_01_4 = {53 00 68 00 61 00 72 00 70 00 48 00 6f 00 75 00 6e 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  SharpHound.exe
	condition:
		any of ($a_*)
 
}