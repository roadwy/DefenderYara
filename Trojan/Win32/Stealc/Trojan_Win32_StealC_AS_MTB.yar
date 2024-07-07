
rule Trojan_Win32_StealC_AS_MTB{
	meta:
		description = "Trojan:Win32/StealC.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b c8 66 2b cf 66 8b f8 b8 03 70 00 00 66 89 0d 90 01 04 66 23 f8 0f b7 e9 8a 02 46 88 04 13 42 0f b7 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}