
rule Trojan_Win32_Zenpak_CAR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 c7 05 [0-04] f6 06 00 00 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 dc 89 4d ec 89 55 d8 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}