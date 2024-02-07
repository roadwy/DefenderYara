
rule VirTool_Win32_HtWorkz_A_MTB{
	meta:
		description = "VirTool:Win32/HtWorkz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 68 65 61 64 73 63 72 65 65 6e 73 68 6f 74 } //01 00  uploadheadscreenshot
		$a_01_1 = {75 73 65 72 61 67 65 6e 74 } //01 00  useragent
		$a_01_2 = {69 70 63 68 65 63 6b 75 72 6c } //01 00  ipcheckurl
		$a_01_3 = {68 65 61 72 74 62 65 61 74 } //01 00  heartbeat
		$a_01_4 = {70 6f 72 74 } //01 00  port
		$a_01_5 = {75 70 6c 6f 61 64 68 65 61 64 66 69 6c 65 } //01 00  uploadheadfile
		$a_01_6 = {78 6f 72 6b 65 79 } //00 00  xorkey
	condition:
		any of ($a_*)
 
}