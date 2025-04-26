
rule Trojan_Win32_Fareit_HJL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.HJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 6d 38 00 8b 34 0a ff 45 38 ff 4d 38 83 04 24 00 81 f6 e7 2d af e6 83 04 24 00 09 34 08 f8 83 34 24 00 83 e9 fc 83 04 24 00 81 f9 f8 80 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}