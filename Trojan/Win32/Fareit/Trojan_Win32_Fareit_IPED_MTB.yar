
rule Trojan_Win32_Fareit_IPED_MTB{
	meta:
		description = "Trojan:Win32/Fareit.IPED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 f4 31 47 00 38 31 47 00 08 34 47 00 d8 33 47 00 } //1
		$a_01_1 = {88 18 eb 16 90 90 90 8b 45 fc 90 90 03 45 f8 90 90 8a 18 90 90 80 f3 81 eb e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}