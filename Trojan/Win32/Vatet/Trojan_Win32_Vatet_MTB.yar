
rule Trojan_Win32_Vatet_MTB{
	meta:
		description = "Trojan:Win32/Vatet!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 39 2c 68 34 32 2c 12 34 32 2c 12 34 32 2c 12 34 32 04 44 34 32 2c 68 34 32 2c 56 34 32 04 44 34 32 2c 68 34 32 04 44 34 32 04 44 34 32 04 44 34 32 2c 12 34 32 2c 12 34 32 2c 12 34 32 88 04 39 41 3b ca 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}