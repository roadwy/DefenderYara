
rule Trojan_Win64_Vidar_SG_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 bc 34 30 03 00 00 44 0f b6 84 34 70 01 00 00 41 31 f8 44 88 84 34 30 03 00 00 48 ff c6 48 83 fe 10 7c ?? e9 ?? ?? ?? ?? 44 0f b6 94 3c 10 02 00 00 48 c1 e2 04 4e 8d 1c 02 46 0f b6 1c 1f 45 31 d3 44 88 9c 3c 98 01 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}