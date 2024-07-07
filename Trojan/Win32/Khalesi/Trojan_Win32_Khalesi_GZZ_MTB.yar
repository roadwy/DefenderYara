
rule Trojan_Win32_Khalesi_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 c7 04 24 02 00 00 00 c7 44 24 90 01 01 2c 02 00 00 e8 90 01 04 51 89 c3 51 8d 74 24 90 01 01 89 04 24 89 74 24 90 01 01 e8 90 01 04 52 52 85 c0 75 90 01 01 31 c0 eb 90 01 01 89 74 24 90 01 01 89 1c 24 e8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}