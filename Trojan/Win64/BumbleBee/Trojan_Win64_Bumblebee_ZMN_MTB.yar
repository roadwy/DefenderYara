
rule Trojan_Win64_Bumblebee_ZMN_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.ZMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 ff c0 49 2b 86 38 01 00 00 49 01 82 40 03 00 00 49 8b 4e 38 48 8b 81 ?? ?? ?? ?? 49 09 86 f8 00 00 00 48 ff 81 ?? ?? ?? ?? 49 63 96 00 04 00 00 49 8b 4e 10 49 8b 46 40 8a 14 0a 42 32 14 08 49 8b 46 50 41 88 14 01 33 d2 49 63 8e 00 04 00 00 } //4
		$a_01_1 = {73 58 74 76 6e 58 6a 48 79 50 } //1 sXtvnXjHyP
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}