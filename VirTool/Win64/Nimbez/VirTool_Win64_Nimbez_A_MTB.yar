
rule VirTool_Win64_Nimbez_A_MTB{
	meta:
		description = "VirTool:Win64/Nimbez.A!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 6d 61 69 6e } //01 00  domain
		$a_01_1 = {75 73 65 72 6e 61 6d 65 } //01 00  username
		$a_01_2 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_01_3 = {68 6f 73 74 6e 61 6d 65 } //01 00  hostname
		$a_01_4 = {75 73 65 72 41 67 65 6e 74 } //01 00  userAgent
		$a_01_5 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //01 00  MiniDumpWriteDump
		$a_01_6 = {40 75 61 63 2d 62 79 70 61 73 73 } //01 00  @uac-bypass
		$a_01_7 = {40 70 65 72 73 69 73 74 2d 73 70 65 } //01 00  @persist-spe
		$a_01_8 = {40 70 65 72 73 69 73 74 2d 72 75 6e } //01 00  @persist-run
		$a_01_9 = {40 73 63 72 65 65 6e 73 68 6f 74 } //01 00  @screenshot
		$a_01_10 = {40 63 6c 69 70 62 6f 61 72 64 } //01 00  @clipboard
		$a_01_11 = {40 75 70 6c 6f 61 64 } //01 00  @upload
		$a_01_12 = {40 64 6f 77 6e 6c 6f 61 64 } //00 00  @download
	condition:
		any of ($a_*)
 
}