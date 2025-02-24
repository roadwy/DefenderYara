
rule Trojan_Win32_BlackMoon_GB_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}