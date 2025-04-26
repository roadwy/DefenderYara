
rule Trojan_Win32_Bsymem_RF_MTB{
	meta:
		description = "Trojan:Win32/Bsymem.RF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 89 45 b4 8a 4d ec 88 4d ff 0f be 55 ff 85 d2 75 0b 8b 45 b0 89 85 bc fe ff ff eb 13 0f be 45 ff 33 45 b0 b9 93 01 00 01 f7 e1 89 45 b0 eb c3 81 bd bc fe ff ff 1b f9 d0 b3 75 3c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}