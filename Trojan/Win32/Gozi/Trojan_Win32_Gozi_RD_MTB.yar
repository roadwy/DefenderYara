
rule Trojan_Win32_Gozi_RD_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 c9 0d 66 19 00 56 57 bf 5f f3 6e 3c 03 cf 0f b7 c1 69 c9 0d 66 19 00 99 6a 07 5e f7 fe 03 cf 0f b7 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c3 c1 ca 05 8b ca d3 c7 8b 4c 24 ?? 2b 31 c1 c8 05 8b c8 33 f8 d3 c6 8b 44 24 ?? 8b 4c 24 ?? 83 e9 08 33 f2 48 89 44 24 ?? 89 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}