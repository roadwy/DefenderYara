
rule Trojan_Win32_Smokeloader_NEE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8d b5 f4 fb ff ff 89 bd f4 fb ff ff e8 ?? ?? ?? ?? 8b 85 f8 fb ff ff 8a 8d f4 fb ff ff 03 c3 30 08 83 7d 0c 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}