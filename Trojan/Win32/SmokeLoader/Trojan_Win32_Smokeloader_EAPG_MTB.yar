
rule Trojan_Win32_Smokeloader_EAPG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.EAPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 14 24 89 4c 24 0c 8b 44 24 0c 31 04 24 8b 04 24 33 44 24 04 83 c4 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}