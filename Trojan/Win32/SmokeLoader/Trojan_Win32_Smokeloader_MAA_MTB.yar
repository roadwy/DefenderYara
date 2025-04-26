
rule Trojan_Win32_Smokeloader_MAA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8d b5 f8 fb ff ff 89 9d f8 fb ff ff e8 ?? ?? ?? ?? 8b 85 f4 fb ff ff 8a 8d f8 fb ff ff 03 c7 30 08 83 7d 0c 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}