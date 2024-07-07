
rule Trojan_Win32_Fareit_JS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.JS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 55 90 01 01 33 94 85 90 01 04 8b 45 90 01 01 88 10 ff 45 90 01 01 46 ff 4d 90 01 01 0f 85 37 ff ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}