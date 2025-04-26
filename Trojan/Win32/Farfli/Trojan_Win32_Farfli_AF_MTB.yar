
rule Trojan_Win32_Farfli_AF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a b8 4e 1e 40 00 c3 c7 45 fc 01 00 00 00 8b 45 08 83 c0 01 89 45 08 eb 99 } //1
		$a_01_1 = {8b c7 8b cf c1 f8 05 83 e1 1f 8b 04 85 a0 1d 43 00 8d 04 c8 8b 0b 89 08 8a 4d 00 88 48 04 47 45 83 c3 04 3b fe 7c ba } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}