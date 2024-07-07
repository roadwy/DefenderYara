
rule Trojan_Win32_Vidar_D_MTB{
	meta:
		description = "Trojan:Win32/Vidar.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 02 32 04 39 88 07 } //2
		$a_01_1 = {8b c8 33 d2 8b c3 f7 f1 8b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}