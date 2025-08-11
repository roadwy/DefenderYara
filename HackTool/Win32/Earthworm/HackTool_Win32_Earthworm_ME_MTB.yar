
rule HackTool_Win32_Earthworm_ME_MTB{
	meta:
		description = "HackTool:Win32/Earthworm.ME!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 6b 69 74 65 72 } //10 rootkiter
		$a_01_1 = {45 61 72 74 68 57 72 6f 6d } //3 EarthWrom
		$a_01_2 = {45 61 72 74 68 57 6f 72 6d } //3 EarthWorm
		$a_01_3 = {43 4f 4e 46 49 52 4d 5f 59 4f 55 5f 41 52 45 5f 53 4f 43 4b 5f 43 4c 49 45 4e 54 } //1 CONFIRM_YOU_ARE_SOCK_CLIENT
		$a_01_4 = {73 73 6f 63 6b 73 64 } //1 ssocksd
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=15
 
}