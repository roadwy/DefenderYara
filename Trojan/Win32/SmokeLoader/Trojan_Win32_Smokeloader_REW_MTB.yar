
rule Trojan_Win32_Smokeloader_REW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.REW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 3b 47 3b 7d 08 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}