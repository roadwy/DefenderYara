
rule Trojan_Win32_Smokeloader_SACF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 46 89 44 24 04 83 6c 24 04 0a 90 83 6c 24 04 3c 8a 44 24 04 30 04 37 83 fb 0f 75 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}