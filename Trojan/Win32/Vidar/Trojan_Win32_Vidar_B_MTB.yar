
rule Trojan_Win32_Vidar_B_MTB{
	meta:
		description = "Trojan:Win32/Vidar.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 80 34 38 5e 5f 5e 5b 8b e5 5d c3 } //1
		$a_01_1 = {2b c8 be 98 6c 14 00 8d 49 00 8a 14 01 88 10 40 4e 75 f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}