
rule Trojan_Win32_Zusy_AO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 40 08 03 45 f8 8b 4d 08 99 f7 79 04 8b 45 08 8b 08 8b 45 f8 8b 75 f4 8b 0c 91 89 0c 86 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}