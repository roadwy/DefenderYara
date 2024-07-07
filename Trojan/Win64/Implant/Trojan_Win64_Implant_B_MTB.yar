
rule Trojan_Win64_Implant_B_MTB{
	meta:
		description = "Trojan:Win64/Implant.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 63 5f 70 61 79 6c 6f 61 64 20 61 64 64 72 } //2 calc_payload addr
		$a_01_1 = {25 2d 32 30 73 20 3a 20 30 78 25 2d 30 31 36 70 } //2 %-20s : 0x%-016p
		$a_01_2 = {65 78 65 63 5f 6d 65 6d 20 61 64 64 72 } //2 exec_mem addr
		$a_01_3 = {48 69 74 20 6d 65 20 31 73 74 21 } //2 Hit me 1st!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}