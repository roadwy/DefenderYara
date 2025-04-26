
rule Trojan_Win32_Tibs_IQ{
	meta:
		description = "Trojan:Win32/Tibs.IQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f 6f 00 0f 7e c0 c9 c2 } //2
		$a_01_1 = {0f 34 c3 8d 0d 00 00 00 00 } //1
		$a_01_2 = {cd 2b c3 8d 0d 00 00 00 00 } //1
		$a_03_3 = {0f 6f 01 0f 7e 45 fc bb ?? ?? ?? ?? 81 f3 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3) >=3
 
}