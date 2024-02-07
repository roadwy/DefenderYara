
rule Backdoor_BAT_ShellClient_A{
	meta:
		description = "Backdoor:BAT/ShellClient.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 73 74 75 72 61 2e } //01 00  costura.
		$a_01_1 = {63 6c 69 65 6e 74 63 6f 72 65 2e 64 6c 6c } //01 00  clientcore.dll
		$a_01_2 = {65 78 74 65 6e 73 69 6f 6e 6c 69 62 2e 64 6c 6c } //01 00  extensionlib.dll
		$a_01_3 = {64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //01 00  dll.compressed
		$a_01_4 = {44 63 53 76 63 2e 44 72 6f 70 62 6f 78 41 70 69 2b 3c 55 70 6c 6f 61 64 3e } //01 00  DcSvc.DropboxApi+<Upload>
		$a_01_5 = {2f 4c 6f 67 54 6f 43 6f 6e 73 6f 6c 65 3d 66 61 6c 73 65 2f } //00 00  /LogToConsole=false/
		$a_00_6 = {5d 04 00 } //00 ed 
	condition:
		any of ($a_*)
 
}