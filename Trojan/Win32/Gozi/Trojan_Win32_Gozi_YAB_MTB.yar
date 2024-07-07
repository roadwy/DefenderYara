
rule Trojan_Win32_Gozi_YAB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8a 8c 30 90 01 04 8b c7 25 3f 00 00 80 79 05 48 83 c8 c0 40 8a 98 90 01 04 68 90 01 04 32 d9 e8 8c 29 00 00 83 c4 04 8b f0 68 90 01 04 e8 7d 29 00 00 83 c4 04 03 f0 68 90 01 04 e8 6e 29 00 00 83 c4 04 03 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}