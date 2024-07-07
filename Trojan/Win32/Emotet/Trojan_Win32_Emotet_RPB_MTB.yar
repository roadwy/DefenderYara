
rule Trojan_Win32_Emotet_RPB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 4a 23 16 83 c6 04 f7 da 8d 52 d7 83 ea 02 83 c2 01 29 ca 31 c9 29 d1 f7 d9 6a 00 8f 03 01 53 00 83 c3 04 83 c0 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}