
rule Trojan_Win32_AveMaria_CC_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.CC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f6 8b 75 f0 8a 04 32 30 04 39 41 8b 75 f8 3b cb 72 e9 8b cf e8 92 fc ff ff 64 8b 0d 30 00 00 00 89 41 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}