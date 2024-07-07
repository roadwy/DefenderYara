
rule Trojan_Win32_IcedID_NC_MTB{
	meta:
		description = "Trojan:Win32/IcedID.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {2c 07 8a d9 2a 1e 2a da 80 c3 40 02 c3 0f b6 f8 } //10
		$a_81_1 = {35 35 5c 34 37 5c 6f 68 2e 70 64 62 } //3 55\47\oh.pdb
		$a_81_2 = {53 75 69 74 70 72 6f 76 65 } //3 Suitprove
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}