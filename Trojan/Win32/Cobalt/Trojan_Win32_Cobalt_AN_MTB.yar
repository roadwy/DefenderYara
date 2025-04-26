
rule Trojan_Win32_Cobalt_AN_MTB{
	meta:
		description = "Trojan:Win32/Cobalt.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 14 33 8a 04 17 8d 4b 01 83 e1 07 d2 c8 43 88 02 3b 5d fc 7c ea } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}