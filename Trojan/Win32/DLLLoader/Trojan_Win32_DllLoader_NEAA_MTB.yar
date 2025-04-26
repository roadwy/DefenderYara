
rule Trojan_Win32_DllLoader_NEAA_MTB{
	meta:
		description = "Trojan:Win32/DllLoader.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b d5 41 89 96 e0 00 00 00 69 47 3c 47 c0 2c 64 3b c8 75 ec } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}