
rule Trojan_Win64_Cobaltstrike_MCH_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.MCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c9 48 8d 95 20 03 00 00 48 03 d1 0f b6 0a 41 88 0b 44 88 02 45 02 03 41 0f b6 d0 44 0f b6 84 15 20 03 00 00 45 30 02 49 ff c2 48 83 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}