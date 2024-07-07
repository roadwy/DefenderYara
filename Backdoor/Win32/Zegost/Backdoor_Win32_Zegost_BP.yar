
rule Backdoor_Win32_Zegost_BP{
	meta:
		description = "Backdoor:Win32/Zegost.BP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 73 63 00 5b 43 61 70 73 4c 6f 63 6b 5d 00 00 50 61 75 73 65 } //1
		$a_01_1 = {c6 45 c6 61 88 45 c7 c6 45 c8 46 c6 45 c9 6f 88 45 ca c6 45 cb 64 } //1
		$a_01_2 = {c6 45 e0 66 c6 45 e1 75 c6 45 e2 63 c6 45 e3 6b c6 45 e4 33 c6 45 e5 36 88 5d e6 c6 45 e7 00 ff 55 b0 6a 64 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}