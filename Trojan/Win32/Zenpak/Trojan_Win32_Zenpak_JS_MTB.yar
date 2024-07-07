
rule Trojan_Win32_Zenpak_JS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.JS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {76 1f 8b 0d 90 01 04 8a 8c 08 8e 1b 0c 00 8b 15 90 01 04 88 0c 10 40 3b 05 90 01 04 72 e1 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}