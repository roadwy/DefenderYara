
rule Trojan_Win32_ArkeiSpyLoader_LK_MTB{
	meta:
		description = "Trojan:Win32/ArkeiSpyLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 04 2c 10 0a c3 32 c1 32 c7 88 06 32 e8 83 c6 02 83 c5 02 eb 0e 8a c8 bf 01 00 00 00 fe c9 c0 e1 04 0a cb 8a 02 84 c0 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}