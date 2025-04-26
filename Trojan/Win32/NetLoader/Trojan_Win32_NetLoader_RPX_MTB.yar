
rule Trojan_Win32_NetLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 4c 24 10 51 68 00 10 00 00 8d 54 24 30 52 33 ff 55 33 f6 89 7c 24 20 ff d3 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}