
rule Trojan_Win32_Blackmoon_MBXH_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 30 34 38 35 37 36 38 39 31 [0-59] 80 56 40 00 00 00 00 00 00 4d 40 01 00 00 00 00 00 00 00 64 73 31 35 5f 36 65 31 76 35 65 77 39 5f 37 34 79 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}