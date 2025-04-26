
rule Trojan_Win32_Smokeloader_SPDD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d d4 fb ff ff 30 04 31 83 ff 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}