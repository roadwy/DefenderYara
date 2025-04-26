
rule Trojan_Win32_Blackmoon_NC_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 86 80 04 00 00 3b f0 73 ?? 80 66 04 00 83 0e ff 83 66 08 00 c6 46 05 0a a1 80 3c 45 00 83 c6 24 05 80 04 00 00 } //3
		$a_01_1 = {2f 2a 72 65 70 31 30 32 31 6c 61 63 65 2a 2f } //1 /*rep1021lace*/
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}