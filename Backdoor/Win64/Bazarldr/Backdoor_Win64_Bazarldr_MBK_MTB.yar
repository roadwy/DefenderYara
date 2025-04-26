
rule Backdoor_Win64_Bazarldr_MBK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 f0 48 c1 f8 [0-01] 41 [0-04] 49 [0-03] 48 39 d3 0f 83 [0-04] 48 89 f0 48 c1 f8 [0-01] 41 90 1b 01 49 90 1b 02 48 39 d3 0f 83 [0-04] 48 89 f0 48 83 c6 [0-01] 48 c1 f8 [0-01] 41 90 1b 01 48 83 c3 [0-01] 48 39 df 0f 8e [0-04] 49 90 1b 02 48 39 d3 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Backdoor_Win64_Bazarldr_MBK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be f3 01 fe 89 f3 c1 e3 [0-01] 01 f3 89 df c1 ff [0-01] 31 df 0f b6 5d 00 48 83 c5 01 84 db 75 } //1
		$a_03_1 = {0f be f3 01 ee 89 f3 c1 e3 [0-01] 01 f3 89 dd c1 fd [0-01] 31 dd 0f b6 19 48 83 c1 01 84 db 75 } //1
		$a_03_2 = {8d 6c ed 00 89 e9 c1 f9 [0-01] 31 e9 89 ce c1 e6 [0-01] 01 ce 81 fe [0-04] 74 [0-01] 48 83 c7 01 4c 39 ff 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}