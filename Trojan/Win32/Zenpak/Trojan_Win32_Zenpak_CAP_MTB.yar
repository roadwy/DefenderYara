
rule Trojan_Win32_Zenpak_CAP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d ec 8b 75 c8 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 c8 88 1c 31 c7 05 [0-04] f6 06 00 00 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d c4 89 75 d8 89 4d d4 89 55 d0 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}