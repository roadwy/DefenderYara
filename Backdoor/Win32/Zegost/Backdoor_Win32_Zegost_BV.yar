
rule Backdoor_Win32_Zegost_BV{
	meta:
		description = "Backdoor:Win32/Zegost.BV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 73 63 00 5b 43 61 70 73 4c 6f 63 6b 5d 00 00 50 61 75 73 65 } //1
		$a_01_1 = {c6 45 d8 47 c6 45 d9 68 c6 45 da 30 c6 45 db 73 } //1
		$a_03_2 = {ff 5c c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 63 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}