
rule Trojan_Win32_QakbotLoader_MTB{
	meta:
		description = "Trojan:Win32/QakbotLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac 02 c3 32 c3 aa e2 90 01 01 5e 5f 90 00 } //1
		$a_03_1 = {ac 84 c0 74 90 01 01 32 d0 c1 c2 90 01 01 eb 90 01 01 8b c2 5e 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}