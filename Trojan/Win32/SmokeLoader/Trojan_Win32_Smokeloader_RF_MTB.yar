
rule Trojan_Win32_Smokeloader_RF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}