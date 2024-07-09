
rule Backdoor_Win64_Bazarldr_MDK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 fe f7 d6 81 e6 [0-04] 89 fb 21 eb 09 f3 31 eb 81 e7 [0-04] 09 df 89 bc 84 [0-04] 48 ff c1 48 ff c0 48 83 f8 [0-01] 75 } //1
		$a_03_1 = {8b 4c 84 2c 89 ca 44 31 fa 21 ca 31 f9 44 21 f9 89 ce 21 d6 31 ca 09 f2 89 d1 31 f9 81 e1 [0-04] 81 e2 [0-04] 09 ca 89 54 [0-02] 48 ff c0 48 83 f8 [0-01] 75 } //1
		$a_03_2 = {89 d6 31 fe 89 f5 81 cd [0-04] 89 d3 81 cb [0-04] 44 21 f3 81 e6 [0-04] 09 de 44 21 f5 81 e2 [0-04] 09 ea 31 f2 89 d5 31 fd 81 e5 [0-04] 81 e2 [0-04] 09 ea 89 [0-03] 4c 01 e1 4c 89 e2 48 29 ca 4c 01 ea 48 f7 da 4a 8d 0c 2a 48 ff c1 48 ff c0 48 83 f8 [0-01] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}