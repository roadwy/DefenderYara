
rule Trojan_Win64_Lazy_ZBA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ZBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c0 49 63 c8 42 0f b6 04 09 42 88 04 0e 48 8b 44 24 90 01 01 88 14 01 4c 8b 4c 24 90 01 01 42 0f b6 0c 0e 48 03 ca 0f b6 c1 42 0f b6 0c 08 41 30 0c 1b 49 ff c3 49 81 fb e7 d6 07 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}