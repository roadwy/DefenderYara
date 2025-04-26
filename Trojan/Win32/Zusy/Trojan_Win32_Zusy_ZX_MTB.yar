
rule Trojan_Win32_Zusy_ZX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e8 03 55 dc 0f b6 02 8b 4d e8 03 4d dc 0f b6 51 ff 33 c2 8b 4d e8 03 4d dc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}