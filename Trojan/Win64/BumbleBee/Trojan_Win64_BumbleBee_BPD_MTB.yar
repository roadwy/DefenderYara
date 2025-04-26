
rule Trojan_Win64_BumbleBee_BPD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8b 0c 02 49 83 c2 04 44 0f af 4f 64 8b 05 c9 c8 0d 00 2b 82 94 00 00 00 2d 83 f4 26 00 09 42 6c 48 8b 05 60 c8 0d 00 45 8b c1 48 63 15 d6 c8 0d 00 41 c1 e8 08 48 8b 88 a0 00 00 00 44 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}