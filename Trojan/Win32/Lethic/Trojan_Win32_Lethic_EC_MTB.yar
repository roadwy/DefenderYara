
rule Trojan_Win32_Lethic_EC_MTB{
	meta:
		description = "Trojan:Win32/Lethic.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 11 01 d0 88 c7 8a 26 80 cc 01 88 d8 f6 e4 88 c4 8a 06 28 e0 88 01 88 f9 88 d8 d2 e0 00 c7 88 3e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}