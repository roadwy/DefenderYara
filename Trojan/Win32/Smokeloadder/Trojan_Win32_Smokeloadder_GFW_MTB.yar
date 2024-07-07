
rule Trojan_Win32_Smokeloadder_GFW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloadder.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 90 01 01 03 54 24 90 01 01 03 fe 31 7c 24 90 01 01 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 4d 8b 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}