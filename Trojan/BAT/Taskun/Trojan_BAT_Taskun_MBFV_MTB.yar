
rule Trojan_BAT_Taskun_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 11 0f 11 0e 11 0f 8e 69 6a 5d d4 91 61 } //1
		$a_03_1 = {5d d4 91 61 28 90 01 01 00 00 0a 07 06 17 6a 58 11 05 6a 5d d4 91 28 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_MBFV_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 00 0d 20 00 4c 00 6f 00 61 00 64 } //10
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_4 = {53 74 72 69 6e 67 54 6f 42 79 74 65 41 72 72 61 79 } //1 StringToByteArray
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}