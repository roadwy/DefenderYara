
rule Trojan_Win32_Smokeloader_YIO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.YIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 69 c9 94 0b 00 00 f7 7c 24 28 8b 54 24 24 30 0a 8b 74 24 34 03 f2 0f af c1 69 c0 ?? ?? ?? ?? 01 44 24 18 ff 44 24 18 8b c1 0f af 44 24 18 83 c0 48 99 f7 fe 29 44 24 1c 3b 4c 24 18 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}