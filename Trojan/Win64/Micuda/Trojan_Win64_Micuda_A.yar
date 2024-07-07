
rule Trojan_Win64_Micuda_A{
	meta:
		description = "Trojan:Win64/Micuda.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 72 61 6e 6b 30 39 35 } //1 frank095
		$a_01_1 = {33 6a 32 6b 32 33 } //1 3j2k23
		$a_01_2 = {44 61 74 61 47 65 6e 20 76 31 2e 30 33 } //1 DataGen v1.03
		$a_01_3 = {63 70 75 6d 69 6e 65 72 2f 32 2e 33 2e 33 } //1 cpuminer/2.3.3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}