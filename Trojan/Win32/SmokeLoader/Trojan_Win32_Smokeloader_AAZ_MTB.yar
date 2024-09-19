
rule Trojan_Win32_Smokeloader_AAZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 e8 c9 ff ff ff 8b 45 08 59 8a 4d fc 03 c6 30 08 83 fb 0f 75 10 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 46 3b f3 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}