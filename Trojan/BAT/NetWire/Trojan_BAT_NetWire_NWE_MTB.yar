
rule Trojan_BAT_NetWire_NWE_MTB{
	meta:
		description = "Trojan:BAT/NetWire.NWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 6f 3a 00 00 0a 25 26 0c 1f 61 6a 08 28 90 01 01 00 00 06 25 26 0d 09 28 3b 00 00 0a 25 90 00 } //5
		$a_01_1 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //1 add_ResourceResolve
		$a_01_2 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 4d 79 } //1 WindowsApplication1.My
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}