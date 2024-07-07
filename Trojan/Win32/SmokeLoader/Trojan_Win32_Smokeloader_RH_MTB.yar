
rule Trojan_Win32_Smokeloader_RH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {24 6a 58 20 c7 90 02 05 3c 46 ae 28 c7 85 90 01 04 78 f4 32 3b c7 85 90 01 04 c4 9f 3a 07 c7 90 02 05 f4 9c fa 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}