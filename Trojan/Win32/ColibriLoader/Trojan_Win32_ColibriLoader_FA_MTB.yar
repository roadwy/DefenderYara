
rule Trojan_Win32_ColibriLoader_FA_MTB{
	meta:
		description = "Trojan:Win32/ColibriLoader.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be c0 33 c3 69 d8 93 01 00 01 41 8a 01 84 c0 75 ee } //3
		$a_01_1 = {30 04 32 42 3b d7 72 ed 8b 7d f0 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}