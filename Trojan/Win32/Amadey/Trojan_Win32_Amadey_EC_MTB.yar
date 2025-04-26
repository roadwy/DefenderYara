
rule Trojan_Win32_Amadey_EC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 02 33 c1 69 c0 91 e9 d1 5b 33 f0 8b c6 c1 e8 0d 33 c6 69 c8 91 e9 d1 5b 8b c1 c1 e8 0f 33 c1 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}