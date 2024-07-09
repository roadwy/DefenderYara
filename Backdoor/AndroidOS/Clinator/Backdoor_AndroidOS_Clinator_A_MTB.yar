
rule Backdoor_AndroidOS_Clinator_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Clinator.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {15 00 00 00 12 12 62 00 ?? ?? 12 01 6e 30 ?? ?? 10 02 0a 00 38 00 0a 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 10 ?? ?? 00 00 0f 02 0d 00 28 fe } //1
		$a_00_1 = {49 6e 65 74 41 64 64 72 65 73 73 } //1 InetAddress
		$a_00_2 = {63 6f 6d 2f 69 76 65 6e 67 6f 2f 61 64 73 } //1 com/ivengo/ads
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}