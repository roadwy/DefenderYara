
rule Trojan_Win32_Smokeloader_CBB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}