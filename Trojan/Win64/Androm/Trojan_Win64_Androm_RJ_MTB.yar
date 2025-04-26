
rule Trojan_Win64_Androm_RJ_MTB{
	meta:
		description = "Trojan:Win64/Androm.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 60 99 83 e2 03 03 c2 c1 f8 02 48 98 48 89 84 24 b0 00 00 00 8b 44 24 60 99 83 e2 03 03 c2 83 e0 03 2b c2 c1 e0 03 0f b6 c8 48 8b 84 24 b0 00 00 00 8b 44 84 20 d3 e8 25 ff 00 00 00 48 63 4c 24 60 48 8b 94 24 d0 00 00 00 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}