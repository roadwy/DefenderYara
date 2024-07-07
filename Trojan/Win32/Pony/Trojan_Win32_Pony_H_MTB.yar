
rule Trojan_Win32_Pony_H_MTB{
	meta:
		description = "Trojan:Win32/Pony.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 10 80 f2 90 01 01 90 05 04 01 90 88 10 90 05 04 01 90 c3 8b c0 53 51 8b d8 54 6a 40 52 53 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}