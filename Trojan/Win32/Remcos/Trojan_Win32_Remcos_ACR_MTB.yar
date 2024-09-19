
rule Trojan_Win32_Remcos_ACR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb d3 46 1a 08 c1 e8 05 b8 98 ff a6 08 81 f3 77 78 21 23 81 ac 24 84 00 00 00 02 be 8c 45 81 f3 85 ee dc 7d 81 84 24 84 00 00 00 02 be 8c 45 8b 84 24 84 00 00 00 8a 8c 24 0b 01 00 00 08 8c 24 1c 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}