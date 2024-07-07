
rule Trojan_Win32_Ekstak_GND_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 b4 94 90 01 04 28 00 00 da 0a 00 90 01 02 0d ca f2 cc 28 00 00 2a 01 00 71 27 49 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}