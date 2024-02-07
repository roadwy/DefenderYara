
rule PWS_Win32_QQpass_GF{
	meta:
		description = "PWS:Win32/QQpass.GF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //01 00 
		$a_00_1 = {61 71 2e 71 71 2e 63 6f 6d 2f 63 6e 32 2f 66 69 6e 64 70 73 77 } //01 00  aq.qq.com/cn2/findpsw
		$a_00_2 = {51 51 2e 65 78 65 } //01 00  QQ.exe
		$a_00_3 = {51 51 31 35 34 36 36 30 35 37 31 37 } //01 00  QQ1546605717
		$a_00_4 = {7a 6a 74 64 30 30 30 } //00 00  zjtd000
	condition:
		any of ($a_*)
 
}