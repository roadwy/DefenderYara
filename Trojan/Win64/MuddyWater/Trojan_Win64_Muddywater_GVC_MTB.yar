
rule Trojan_Win64_Muddywater_GVC_MTB{
	meta:
		description = "Trojan:Win64/Muddywater.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 08 02 00 00 48 ff c0 48 89 85 08 02 00 00 48 8b 85 88 01 00 00 48 39 85 08 02 00 00 73 35 48 8b 85 08 02 00 00 48 8b 8d 68 01 00 00 48 03 c8 48 8b c1 0f b6 00 33 85 44 01 00 00 48 8b 8d 08 02 00 00 48 8b 95 68 01 00 00 48 03 d1 48 8b ca 88 01 eb aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}