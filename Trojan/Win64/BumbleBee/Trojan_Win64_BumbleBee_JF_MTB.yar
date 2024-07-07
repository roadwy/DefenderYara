
rule Trojan_Win64_BumbleBee_JF_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.JF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 63 c0 0f b7 05 90 01 04 41 0f af c1 41 ff c1 99 42 f7 3c 81 41 89 02 4d 8d 52 90 01 01 4c 8b 05 90 00 } //1
		$a_03_1 = {41 0f b6 0e 48 8d 04 4e 32 1c 01 41 0f b6 00 4d 8d 40 90 01 01 49 0b c1 49 89 04 d3 48 ff c2 49 3b d2 7d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}