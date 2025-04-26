
rule Trojan_AndroidOS_Rewardsteal_Z{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.Z,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 62 69 73 6d 73 32 6e 65 77 2f 43 68 6d 33 6b } //2 sbisms2new/Chm3k
		$a_01_1 = {41 6d 61 6e 2d 73 6d 73 2d 31 62 6f 78 73 62 69 } //2 Aman-sms-1boxsbi
		$a_01_2 = {73 62 69 73 6d 73 32 6e 65 77 2f 50 61 72 6b 41 63 } //2 sbisms2new/ParkAc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}