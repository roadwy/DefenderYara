
rule Trojan_Win32_Cobaltstrike_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 3c 18 8a cb 88 44 24 19 88 4c 3c 18 8a 5c 24 19 0f b6 c1 0f b6 fb 03 c7 0f b6 c0 0f b6 44 04 18 30 84 34 18 02 00 00 0f b6 84 34 18 02 00 00 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}