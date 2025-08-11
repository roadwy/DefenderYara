
rule Trojan_Win32_Zusy_AS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c3 83 e3 0f 0f b6 3c 31 89 fd 83 e5 0f 01 eb 21 c5 01 ed 29 eb 89 c5 c1 ed 04 33 2c 9d fc 16 45 00 89 e8 83 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}