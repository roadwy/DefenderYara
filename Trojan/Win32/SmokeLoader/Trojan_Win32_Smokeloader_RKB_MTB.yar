
rule Trojan_Win32_Smokeloader_RKB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.RKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 c7 04 24 b6 e4 fa 1b 81 24 24 ae 8e db 1e 81 04 24 50 b4 bd 7f c1 24 24 07 81 34 24 bb 6a 5c 23 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}