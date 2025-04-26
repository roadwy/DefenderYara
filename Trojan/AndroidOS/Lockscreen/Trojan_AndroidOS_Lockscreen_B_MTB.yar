
rule Trojan_AndroidOS_Lockscreen_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Lockscreen.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 62 65 6e 64 65 6c 5f 73 6f 66 74 77 61 72 65 2f 61 6e 6c 6f 63 6b 65 72 } //1 com/bendel_software/anlocker
		$a_00_1 = {4c 6f 63 6b 65 72 53 65 72 76 69 63 65 24 31 30 30 30 30 30 30 30 30 } //1 LockerService$100000000
		$a_00_2 = {61 64 72 74 24 65 6e 61 62 6c 65 64 } //1 adrt$enabled
		$a_00_3 = {75 6e 63 6c 6f 63 6b } //1 unclock
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}