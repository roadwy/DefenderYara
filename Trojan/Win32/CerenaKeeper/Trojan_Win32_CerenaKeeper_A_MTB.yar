
rule Trojan_Win32_CerenaKeeper_A_MTB{
	meta:
		description = "Trojan:Win32/CerenaKeeper.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 4c 07 24 0f 4d f2 8d 4d d0 57 e8 16 fe ff ff 80 7d d4 00 74 5a 8b 07 8b 40 04 b9 c0 01 00 00 23 4c 07 14 83 f9 40 75 0d 89 75 e0 eb 53 0f 1f 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}