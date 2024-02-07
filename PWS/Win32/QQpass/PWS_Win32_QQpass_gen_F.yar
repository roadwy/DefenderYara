
rule PWS_Win32_QQpass_gen_F{
	meta:
		description = "PWS:Win32/QQpass.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {6c 79 6a 7a 79 71 31 40 31 32 36 2e 63 6f 6d } //02 00  lyjzyq1@126.com
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c 50 4c 41 54 46 4f 52 4d 5f 54 59 50 45 5f 4c 49 53 54 5c 31 5c 54 79 70 65 50 61 74 68 } //02 00  SOFTWARE\TENCENT\PLATFORM_TYPE_LIST\1\TypePath
		$a_01_2 = {2f 53 54 41 52 54 20 51 51 55 49 4e 3a } //02 00  /START QQUIN:
		$a_01_3 = {3f 71 71 69 6e 66 3d } //00 00  ?qqinf=
	condition:
		any of ($a_*)
 
}