
rule Backdoor_Win32_Zegost_F_dll{
	meta:
		description = "Backdoor:Win32/Zegost.F!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 2f 75 70 64 61 74 61 2e 61 73 70 78 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 } //01 00  %s/updata.aspx?mac=%s&ver=%s
		$a_01_1 = {25 73 2f 77 6f 72 6b 2e 61 73 70 78 3f 71 75 65 72 79 3d 25 73 } //01 00  %s/work.aspx?query=%s
		$a_01_2 = {63 68 65 63 6b 75 70 64 61 74 65 } //01 00  checkupdate
		$a_01_3 = {66 70 72 6f 78 79 2e 64 6c } //00 00  fproxy.dl
	condition:
		any of ($a_*)
 
}