
rule Trojan_Win64_FoxChair_A_dha{
	meta:
		description = "Trojan:Win64/FoxChair.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 6f 75 6e 64 20 45 53 58 69 25 64 2e 25 64 20 62 75 69 6c 64 2d 25 64 } //1 found ESXi%d.%d build-%d
		$a_01_1 = {76 6d 6b 65 72 6e 65 6c 20 62 61 73 65 3a 20 25 70 2c 71 70 42 72 6f 6b 65 72 4c 69 73 74 3a 20 25 70 } //1 vmkernel base: %p,qpBrokerList: %p
		$a_01_2 = {76 6d 78 20 62 61 73 65 20 69 73 3a 20 25 70 } //1 vmx base is: %p
		$a_01_3 = {6d 61 78 44 6f 6d 61 69 6e 3a 20 25 30 38 78 } //1 maxDomain: %08x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}