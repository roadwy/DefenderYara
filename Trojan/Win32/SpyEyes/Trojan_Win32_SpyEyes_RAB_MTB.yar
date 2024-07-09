
rule Trojan_Win32_SpyEyes_RAB_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ca 03 c1 8b 8c 24 ?? ?? ?? ?? 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 5e 33 cc e8 ?? ?? ?? ?? 81 c4 30 08 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}