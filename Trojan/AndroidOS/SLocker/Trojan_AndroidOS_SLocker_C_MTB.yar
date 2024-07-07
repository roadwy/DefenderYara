
rule Trojan_AndroidOS_SLocker_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SLocker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 66 61 6b 65 64 61 6d 61 67 65 } //1 com.fakedamage
		$a_01_1 = {67 6f 62 6c 75 65 73 6d 73 } //1 gobluesms
		$a_01_2 = {67 6f 6d 69 73 73 63 61 6c 6c 73 6d 73 } //1 gomisscallsms
		$a_01_3 = {67 6f 73 68 61 6b 65 6d 65 } //1 goshakeme
		$a_00_4 = {63 6f 6d 2e 6d 69 73 73 63 61 6c 6c 73 6d 73 } //1 com.misscallsms
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}