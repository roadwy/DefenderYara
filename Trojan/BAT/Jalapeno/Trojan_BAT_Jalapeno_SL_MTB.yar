
rule Trojan_BAT_Jalapeno_SL_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 36 37 35 32 38 32 61 63 2d 61 33 34 35 2d 34 39 31 62 2d 39 32 39 32 2d 66 31 65 35 34 64 31 37 63 31 63 63 } //2 $675282ac-a345-491b-9292-f1e54d17c1cc
		$a_81_1 = {4c 61 62 30 36 5f 42 61 69 30 31 } //2 Lab06_Bai01
		$a_81_2 = {43 6f 6e 74 72 6f 6c 5f 56 69 65 77 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Control_Viewer.Properties.Resources
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}