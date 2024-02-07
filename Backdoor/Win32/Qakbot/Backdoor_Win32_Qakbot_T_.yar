
rule Backdoor_Win32_Qakbot_T_{
	meta:
		description = "Backdoor:Win32/Qakbot.T!!Qakbot.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 62 6f 74 5f 76 65 72 73 69 6f 6e 3d 5b 25 73 5d } //01 00  qbot_version=[%s]
		$a_01_1 = {00 75 70 64 62 6f 74 00 } //01 00  甀摰潢t
		$a_01_2 = {00 5f 71 62 6f 74 00 } //01 00 
		$a_01_3 = {25 73 5f 25 73 5f 25 75 2e 6b 63 62 } //01 00  %s_%s_%u.kcb
		$a_01_4 = {26 6e 3d 25 73 26 6f 73 3d 25 73 26 62 67 3d 25 73 26 69 74 3d 25 } //01 00  &n=%s&os=%s&bg=%s&it=%
		$a_01_5 = {20 75 73 65 72 3d 5b 25 73 5d 20 70 61 73 73 3d 5b 25 73 5d } //05 00   user=[%s] pass=[%s]
	condition:
		any of ($a_*)
 
}