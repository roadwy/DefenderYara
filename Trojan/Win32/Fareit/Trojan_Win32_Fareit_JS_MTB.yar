
rule Trojan_Win32_Fareit_JS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.JS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 55 ?? 33 94 85 ?? ?? ?? ?? 8b 45 ?? 88 10 ff 45 ?? 46 ff 4d ?? 0f 85 37 ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}