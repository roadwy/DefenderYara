
rule Trojan_Win32_Disco_RPX_MTB{
	meta:
		description = "Trojan:Win32/Disco.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d6 6a 00 6a 04 8d 84 24 7c 02 00 00 c7 84 24 7c 02 00 00 00 00 00 00 50 ff 74 24 44 53 ff d6 8b 84 24 74 02 00 00 8b 7c 24 3c 89 44 24 10 8b 84 24 7c 02 00 00 05 f4 00 00 00 c7 44 24 14 40 00 00 00 89 44 24 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}