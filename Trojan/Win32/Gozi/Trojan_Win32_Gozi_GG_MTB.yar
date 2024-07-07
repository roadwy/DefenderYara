
rule Trojan_Win32_Gozi_GG_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 28 90 02 19 0f 10 04 31 89 54 24 2c 89 44 24 28 66 8b 5c 24 26 66 81 f3 90 01 02 f3 0f 6f 4c 31 10 66 89 5c 24 26 8b 44 24 18 f3 0f 7f 04 30 8a 44 24 25 b4 90 01 01 f6 e4 88 44 24 25 8b 54 24 18 f3 0f 7f 4c 32 10 83 c6 90 01 01 8a 44 24 25 0c 90 01 01 88 44 24 25 8b 7c 24 08 39 fe 89 74 24 10 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}