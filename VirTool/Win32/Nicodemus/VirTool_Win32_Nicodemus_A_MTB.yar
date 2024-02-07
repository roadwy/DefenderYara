
rule VirTool_Win32_Nicodemus_A_MTB{
	meta:
		description = "VirTool:Win32/Nicodemus.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 69 63 6f 64 65 6d 75 73 } //01 00  nicodemus
		$a_01_1 = {62 65 61 63 6f 6e } //01 00  beacon
		$a_01_2 = {40 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  @powershell.exe
		$a_01_3 = {6e 65 77 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  newConnection
		$a_01_4 = {40 73 6c 65 65 70 } //01 00  @sleep
		$a_01_5 = {40 63 6f 6e 74 61 63 74 } //01 00  @contact
		$a_01_6 = {40 61 64 64 72 65 73 73 } //00 00  @address
	condition:
		any of ($a_*)
 
}