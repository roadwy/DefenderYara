
rule Backdoor_Win32_Bifrose_IH{
	meta:
		description = "Backdoor:Win32/Bifrose.IH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 c1 80 30 66 41 3b 4d ec 72 ef } //1
		$a_03_1 = {80 7d 84 e8 74 07 c7 45 b4 90 90 90 90 90 90 90 90 } //1
		$a_01_2 = {c6 45 d4 6a 80 4d d5 ff c6 45 d6 e8 } //1
		$a_01_3 = {59 59 8d 8d e4 fe ff ff 49 49 c6 04 08 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}