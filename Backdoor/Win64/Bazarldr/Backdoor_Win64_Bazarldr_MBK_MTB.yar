
rule Backdoor_Win64_Bazarldr_MBK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 f0 48 c1 f8 90 02 01 41 90 02 04 49 90 02 03 48 39 d3 0f 83 90 02 04 48 89 f0 48 c1 f8 90 02 01 41 90 1b 01 49 90 1b 02 48 39 d3 0f 83 90 02 04 48 89 f0 48 83 c6 90 02 01 48 c1 f8 90 02 01 41 90 1b 01 48 83 c3 90 02 01 48 39 df 0f 8e 90 02 04 49 90 1b 02 48 39 d3 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Backdoor_Win64_Bazarldr_MBK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be f3 01 fe 89 f3 c1 e3 90 02 01 01 f3 89 df c1 ff 90 02 01 31 df 0f b6 5d 00 48 83 c5 01 84 db 75 90 00 } //1
		$a_03_1 = {0f be f3 01 ee 89 f3 c1 e3 90 02 01 01 f3 89 dd c1 fd 90 02 01 31 dd 0f b6 19 48 83 c1 01 84 db 75 90 00 } //1
		$a_03_2 = {8d 6c ed 00 89 e9 c1 f9 90 02 01 31 e9 89 ce c1 e6 90 02 01 01 ce 81 fe 90 02 04 74 90 02 01 48 83 c7 01 4c 39 ff 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}