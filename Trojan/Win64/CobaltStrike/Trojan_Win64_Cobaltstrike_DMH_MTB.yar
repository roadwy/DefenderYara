
rule Trojan_Win64_Cobaltstrike_DMH_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c3 41 0f b6 04 10 88 04 17 45 88 1c 10 48 8b 54 24 30 0f b6 0c 17 41 0f b6 04 10 48 03 c8 0f b6 c1 44 0f b6 04 10 49 8b ce 49 83 7e 18 0f 76 03 49 8b 0e 45 30 04 09 41 ff c2 49 ff c1 49 63 c2 49 3b 47 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}