
rule Trojan_Win64_Injector_LM_MTB{
	meta:
		description = "Trojan:Win64/Injector.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 09 41 ff c0 83 e1 0f 4a 0f be 84 31 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 4c 2b c8 41 8b 51 fc d3 ea ff ca 45 3b c3 } //10
		$a_03_1 = {4a 0f be 84 19 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 48 2b d0 8b 42 fc 4c 8d 42 04 d3 e8 49 89 51 08 41 89 41 20 8b 02 4d 89 41 08 41 89 41 24 49 83 ea 01 } //15
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*15) >=25
 
}