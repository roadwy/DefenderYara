
rule Trojan_Win32_Vidar_GJN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c6 8b f8 33 d2 8b c1 f7 f7 8b 44 24 18 8d 34 19 41 8a 14 02 8b 44 24 1c 32 14 30 88 16 3b cd } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}