
rule Trojan_Win32_Smokeloader_GMK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {32 98 72 16 98 7b 3e 8a fd 01 bb 32 01 ad b6 7b } //0a 00 
		$a_01_1 = {08 3c de 8a e3 00 32 15 e7 84 f0 7e 04 5e 78 } //00 00 
	condition:
		any of ($a_*)
 
}