
rule Trojan_Win64_BrutRatel_YAE_MTB{
	meta:
		description = "Trojan:Win64/BrutRatel.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 } //1
		$a_03_1 = {48 29 c7 0f b6 44 3c ?? 42 32 04 09 48 8b 54 24 ?? 88 04 0a } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}