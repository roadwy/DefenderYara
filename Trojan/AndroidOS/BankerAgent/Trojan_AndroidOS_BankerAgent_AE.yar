
rule Trojan_AndroidOS_BankerAgent_AE{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.AE,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 31 70 32 65 33 6e 34 74 35 68 36 69 37 72 38 64 39 6c 30 6f 31 61 32 64 33 69 34 6e 35 67 36 70 37 61 38 67 39 65 30 66 69 76 65 } //2 o1p2e3n4t5h6i7r8d9l0o1a2d3i4n5g6p7a8g9e0five
		$a_01_1 = {55 52 4c 5f 41 54 4d 61 63 } //2 URL_ATMac
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}