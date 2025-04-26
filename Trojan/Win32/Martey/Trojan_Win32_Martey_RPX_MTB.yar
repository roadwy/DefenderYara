
rule Trojan_Win32_Martey_RPX_MTB{
	meta:
		description = "Trojan:Win32/Martey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 55 8d 44 24 1c 50 ff 74 24 28 ff d3 6a 15 58 66 89 44 24 14 66 89 44 24 16 8d 84 24 94 00 00 00 89 44 24 18 8d 84 24 b8 00 00 00 50 55 8d 44 24 1c 50 ff 74 24 28 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}