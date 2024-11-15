
rule Trojan_Win32_Smokeloader_SFSB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SFSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 2f 89 44 24 0c 8b 44 24 10 31 44 24 0c 8a 4c 24 0c 88 0c 2f 83 fb 0f 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}