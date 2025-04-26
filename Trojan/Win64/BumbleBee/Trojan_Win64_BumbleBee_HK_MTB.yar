
rule Trojan_Win64_BumbleBee_HK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 44 33 db 4c 89 54 24 ?? 4c 23 c0 49 8b cc 44 89 5c 24 } //1
		$a_03_1 = {8b cd 83 c6 ?? 2b 88 ?? ?? ?? ?? 41 2b ce 31 0d ?? ?? ?? ?? 41 3b f7 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}