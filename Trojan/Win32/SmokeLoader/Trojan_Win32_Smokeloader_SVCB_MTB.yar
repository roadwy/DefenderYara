
rule Trojan_Win32_Smokeloader_SVCB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SVCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 2c 24 46 0f be 04 32 89 44 24 ?? 8b 04 24 31 44 24 ?? 8a 4c 24 ?? 88 0c 32 42 3b d7 7c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}