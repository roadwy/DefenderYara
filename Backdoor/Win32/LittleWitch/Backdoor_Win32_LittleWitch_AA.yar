
rule Backdoor_Win32_LittleWitch_AA{
	meta:
		description = "Backdoor:Win32/LittleWitch.AA,SIGNATURE_TYPE_PEHSTR,ffffff9b 00 ffffff9b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {05 00 00 00 52 65 67 69 73 00 00 00 ff ff ff ff 03 00 00 00 74 65 72 00 ff ff ff ff 07 00 00 00 53 65 72 76 69 63 65 00 ff ff ff ff 07 00 00 00 50 72 6f 63 65 73 73 00 } //50
		$a_01_1 = {0e 00 00 00 65 63 68 6f 20 73 7c 66 6f 72 6d 61 74 20 00 00 ff ff ff ff 04 00 00 00 3a 20 2f 51 } //50
		$a_01_2 = {05 00 00 00 2a 2e 75 69 6e 00 00 00 ff ff ff ff 03 00 00 00 63 3a 5c 00 } //50
		$a_01_3 = {45 78 70 6c 6f 72 65 57 43 6c 61 73 73 } //1 ExploreWClass
		$a_01_4 = {4d 53 4e 00 } //1 卍N
		$a_01_5 = {56 45 52 4c 57 53 45 52 56 45 52 36 } //1 VERLWSERVER6
		$a_01_6 = {50 41 53 53 57 4f 52 44 43 41 48 59 4e 41 } //1 PASSWORDCAHYNA
		$a_01_7 = {6c 69 74 74 6c 65 77 69 74 63 68 } //1 littlewitch
		$a_01_8 = {4e 69 63 6b 6e 61 6d 65 } //1 Nickname
		$a_01_9 = {57 41 52 4e 49 4e 47 } //1 WARNING
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=155
 
}