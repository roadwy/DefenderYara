
rule Trojan_Win32_AveMaria_NEDL_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 40 89 45 f4 8b 45 f4 3b 45 e0 73 25 8b 45 f4 99 6a 0c 59 f7 f9 8b 45 e4 0f b6 04 10 8b 4d dc 03 4d f4 0f b6 09 33 c8 8b 45 dc 03 45 f4 88 08 eb cc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}