
rule Trojan_Win32_SpyEyes_RAB_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ca 03 c1 8b 8c 24 90 01 04 25 ff 00 00 00 8a 80 90 01 04 5e 33 cc e8 90 01 04 81 c4 30 08 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}