
rule Trojan_Win32_LokiBot_RPU_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 55 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 81 f2 ?? ?? ?? ?? 88 55 ff 0f b6 45 ff c1 f8 07 0f b6 4d ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}