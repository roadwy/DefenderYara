
rule Trojan_Win64_OysterLoader_YAB_MTB{
	meta:
		description = "Trojan:Win64/OysterLoader.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4 } //1
		$a_03_1 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}