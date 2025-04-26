
rule Trojan_Win32_Smokeloader_GPX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 04 1e 83 ff 0f 75 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}