
rule PWS_Win32_QQpass_FR{
	meta:
		description = "PWS:Win32/QQpass.FR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2e 2d 63 2d 6f 2d 6d 2d 2f 71 2d 71 00 } //01 00 
		$a_01_1 = {2e 61 73 70 3f 4c 6f 67 69 6e 5f 4d 61 72 6b 3d } //01 00  .asp?Login_Mark=
		$a_01_2 = {28 22 71 6c 6f 67 69 6e 5f 6c 6f 61 64 69 6e 67 22 29 2e 76 61 6c 75 65 3d 70 74 2e 6c 69 73 74 5b } //01 00  ("qlogin_loading").value=pt.list[
		$a_01_3 = {5d 2e 6b 65 79 2b 22 2d 22 2b 70 74 2e 6c 69 73 74 5b } //01 00  ].key+"-"+pt.list[
		$a_01_4 = {48 48 45 78 65 63 53 63 72 69 70 74 } //01 00  HHExecScript
		$a_01_5 = {25 54 57 65 62 42 72 6f 77 73 65 72 50 72 69 6e 74 54 65 6d 70 6c 61 74 65 49 6e 73 74 61 6e 74 69 61 74 69 6f 6e 00 } //01 00 
		$a_01_6 = {54 57 65 62 42 72 6f 77 73 65 72 4f 6e 46 75 6c 6c 53 63 72 65 65 6e 00 } //00 00  坔扥牂睯敳佲䙮汵卬牣敥n
	condition:
		any of ($a_*)
 
}