
rule Trojan_Win32_Smokeloader_XU_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.XU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d3 e8 ?? ?? ?? ?? 8b 4d ?? 30 04 0e 46 3b f7 ?? ?? 5b 5f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}