
rule Trojan_Win32_QakbotLoader_MTB{
	meta:
		description = "Trojan:Win32/QakbotLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac 02 c3 32 c3 aa e2 ?? 5e 5f } //1
		$a_03_1 = {ac 84 c0 74 ?? 32 d0 c1 c2 ?? eb ?? 8b c2 5e 5a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}