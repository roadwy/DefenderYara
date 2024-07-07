
rule Trojan_Win32_Gozi_DA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8b 15 90 01 04 a1 90 01 04 42 89 15 90 01 04 c1 e9 90 01 01 88 0c 10 a1 90 01 04 8b 0d 90 01 04 05 a6 14 f6 ff 31 05 90 01 04 41 a1 90 01 04 89 0d 90 01 04 88 1c 08 8b 15 90 01 04 42 89 15 90 01 04 81 fe 90 01 04 7d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}