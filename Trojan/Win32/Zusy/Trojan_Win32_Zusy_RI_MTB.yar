
rule Trojan_Win32_Zusy_RI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 ec b9 21 00 00 c7 45 e4 00 00 00 00 c7 45 f4 c0 13 00 00 c7 45 f8 c1 13 00 00 8b 55 f4 2b 55 f8 89 55 f4 c7 45 fc 00 00 00 00 c7 45 e8 29 21 00 00 8b 45 f8 2b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}