
rule VirTool_Win32_HtWorkz_A_MTB{
	meta:
		description = "VirTool:Win32/HtWorkz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 68 65 61 64 73 63 72 65 65 6e 73 68 6f 74 } //1 uploadheadscreenshot
		$a_01_1 = {75 73 65 72 61 67 65 6e 74 } //1 useragent
		$a_01_2 = {69 70 63 68 65 63 6b 75 72 6c } //1 ipcheckurl
		$a_01_3 = {68 65 61 72 74 62 65 61 74 } //1 heartbeat
		$a_01_4 = {70 6f 72 74 } //1 port
		$a_01_5 = {75 70 6c 6f 61 64 68 65 61 64 66 69 6c 65 } //1 uploadheadfile
		$a_01_6 = {78 6f 72 6b 65 79 } //1 xorkey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}