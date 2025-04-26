
rule Backdoor_Win64_Havoc_AJ_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 ff c2 88 94 03 f0 00 00 00 31 c0 48 63 d0 ff c0 8a 54 14 30 41 30 55 00 49 ff c5 e9 } //2
		$a_01_1 = {31 ca 88 50 fe 44 89 c2 45 01 c0 c0 fa 07 83 e2 1b 44 31 c2 41 31 d1 44 88 48 ff 48 39 44 24 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}