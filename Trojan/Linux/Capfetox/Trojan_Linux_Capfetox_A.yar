
rule Trojan_Linux_Capfetox_A{
	meta:
		description = "Trojan:Linux/Capfetox.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 69 00 6e 00 67 00 } //5 ping
		$a_02_1 = {64 00 6e 00 73 00 2e 00 [0-08] 2e 00 65 00 75 00 2e 00 6f 00 72 00 67 00 } //5
		$a_00_2 = {61 00 6d 00 35 00 6b 00 61 00 53 00 42 00 38 00 49 00 47 00 4a 00 68 00 63 00 32 00 67 00 3d 00 } //10 am5kaSB8IGJhc2g=
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*10) >=10
 
}