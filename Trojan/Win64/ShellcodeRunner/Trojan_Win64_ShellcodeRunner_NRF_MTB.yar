
rule Trojan_Win64_ShellcodeRunner_NRF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 b8 c2 bb cb 4c d8 ac 07 02 } //2
		$a_01_1 = {48 bb 58 d0 d4 b2 ac ef ff ff } //1
		$a_01_2 = {48 b8 5c 39 25 4a bd 1e be 17 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}