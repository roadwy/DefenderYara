
rule Trojan_Win32_Neoreblamy_NRO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 4d d8 d3 f8 33 45 d0 0b 45 c8 } //1
		$a_01_1 = {7d 67 83 65 d8 00 eb 07 8b 45 d8 40 89 45 d8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}