
rule Trojan_Win32_Smokeloader_PAFC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PAFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 7c 8b 8d 78 fe ff ff 5f 5e 89 18 89 48 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}