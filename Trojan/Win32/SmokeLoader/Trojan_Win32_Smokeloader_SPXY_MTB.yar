
rule Trojan_Win32_Smokeloader_SPXY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8b 4d fc 03 45 dc 33 45 ec 33 c8 8d 45 e8 89 4d fc 2b f1 e8 ?? ?? ?? ?? 83 eb 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}