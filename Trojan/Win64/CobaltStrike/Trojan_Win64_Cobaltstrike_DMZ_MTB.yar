
rule Trojan_Win64_Cobaltstrike_DMZ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 19 41 88 04 19 44 88 14 19 41 0f b6 0c 19 49 03 ca 0f b6 c1 8a 0c 18 49 8b c6 49 83 7e 18 0f 76 03 49 8b 06 30 0c 02 41 ff c0 48 ff c2 49 63 c0 48 3b 45 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}