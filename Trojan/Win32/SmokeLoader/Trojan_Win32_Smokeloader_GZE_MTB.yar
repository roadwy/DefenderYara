
rule Trojan_Win32_Smokeloader_GZE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {65 00 72 00 c7 05 90 01 04 6e 00 65 00 c7 05 90 01 04 6c 00 33 00 c7 05 90 01 04 32 00 2e 00 c7 05 90 01 04 64 00 6c 00 c7 05 90 01 04 6c 00 00 00 66 a3 90 01 04 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}