
rule Trojan_Win32_Vidar_AVR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 7c 63 40 00 40 37 40 00 34 37 40 00 8c 63 40 00 90 34 40 00 cc 34 40 00 12 54 4f 58 44 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}