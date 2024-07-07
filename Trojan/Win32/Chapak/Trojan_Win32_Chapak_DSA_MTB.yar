
rule Trojan_Win32_Chapak_DSA_MTB{
	meta:
		description = "Trojan:Win32/Chapak.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 f8 8c eb 73 22 8b 4d f8 83 25 90 01 04 00 8b c7 d3 e0 8b cf c1 e9 05 03 8d 14 fe ff ff 03 85 0c fe ff ff 33 c1 8b 8d 38 fe ff ff 03 cf 33 c1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}