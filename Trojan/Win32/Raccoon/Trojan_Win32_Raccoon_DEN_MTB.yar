
rule Trojan_Win32_Raccoon_DEN_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DEN!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 1c fe ff ff 8b d1 c1 e2 04 03 95 0c fe ff ff 8b c1 c1 e8 05 03 85 10 fe ff ff 03 cb 33 d1 33 d0 89 45 f4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}