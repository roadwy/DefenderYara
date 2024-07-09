
rule Trojan_Win32_SpyEyes_RAA_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ca 03 c1 8b 4d ?? 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}