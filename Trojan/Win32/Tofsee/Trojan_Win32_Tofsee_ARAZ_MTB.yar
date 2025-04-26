
rule Trojan_Win32_Tofsee_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 2b fe 8b 44 24 70 29 44 24 0c 83 6c 24 60 01 0f 85 53 fb ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Tofsee_ARAZ_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 81 04 24 61 70 70 63 68 40 95 41 00 59 8f 41 01 51 ff 15 50 60 40 00 } //2
		$a_01_1 = {73 74 76 70 61 72 6a 75 79 74 6e 62 65 6c 6a } //2 stvparjuytnbelj
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}