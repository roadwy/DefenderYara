
rule Trojan_Win32_Raccoon_DER_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DER!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f0 8b c7 c1 e8 05 89 45 f8 8b 85 08 fe ff ff 01 45 f8 8b c7 c1 e0 04 03 85 10 fe ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}