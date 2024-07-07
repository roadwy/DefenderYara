
rule Trojan_Win32_Hulzic{
	meta:
		description = "Trojan:Win32/Hulzic,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 3f 4d 75 35 80 7f 01 5a 75 2f 8b 4d fc 33 c0 83 c1 f0 3b cb 76 23 80 3c 07 60 75 18 80 7c 07 01 e8 75 11 80 7c 38 06 61 75 0a 81 7c 38 0c e2 45 cc 63 74 15 40 3b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}