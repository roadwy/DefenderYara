
rule Trojan_Win64_Lazy_AV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 01 fe c8 88 01 48 ff c1 48 ff ca 75 f1 } //1
		$a_01_1 = {53 44 48 45 48 52 45 4a 52 49 45 54 37 49 4a 59 52 49 4b 37 59 37 49 36 55 4b 4b 54 48 4b 4a 48 54 47 4b 47 } //1 SDHEHREJRIET7IJYRIK7Y7I6UKKTHKJHTGKG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}