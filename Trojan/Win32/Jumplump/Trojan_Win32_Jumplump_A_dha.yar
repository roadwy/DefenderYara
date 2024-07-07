
rule Trojan_Win32_Jumplump_A_dha{
	meta:
		description = "Trojan:Win32/Jumplump.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {66 3d 4d 5a e9 90 01 03 ff 90 00 } //1
		$a_02_1 = {48 81 ee 02 10 00 00 e9 90 01 03 90 03 01 01 ff 00 90 00 } //1
		$a_01_2 = {48 81 ec 10 04 00 00 e9 } //1
		$a_01_3 = {41 bf 38 68 0d 16 } //1
		$a_01_4 = {41 bf aa c5 e2 5d } //1
		$a_01_5 = {41 bf 08 87 1d 60 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}