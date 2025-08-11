
rule Trojan_Win32_LummaC_EAAT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d7 89 7c 24 04 8b 54 24 04 80 c2 04 88 94 04 01 00 00 80 40 49 } //5
		$a_01_1 = {8d 14 7a 42 21 f2 89 54 24 04 8b 54 24 04 80 c2 a6 88 94 04 52 ff ff ff 40 49 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}