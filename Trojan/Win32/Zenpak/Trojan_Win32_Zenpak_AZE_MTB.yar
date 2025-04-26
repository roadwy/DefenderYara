
rule Trojan_Win32_Zenpak_AZE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 cd 02 2d ?? 49 5f 10 88 2d ?? 49 5f 10 88 0d ?? 49 5f 10 a2 ?? 49 5f 10 c7 05 ?? 49 5f 10 09 1b 00 00 c7 05 ?? 49 5f 10 5f 0d 00 00 0f b6 c4 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}