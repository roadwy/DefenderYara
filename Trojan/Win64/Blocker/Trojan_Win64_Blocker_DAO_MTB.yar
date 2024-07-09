
rule Trojan_Win64_Blocker_DAO_MTB{
	meta:
		description = "Trojan:Win64/Blocker.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 84 24 14 05 00 00 ff c2 48 ff c1 30 41 ff 8b 5c 24 30 3b d3 72 } //2
		$a_03_1 = {48 89 5c 24 30 48 8d 0d [0-04] 45 8d 41 01 ba 00 00 00 c0 89 5c 24 28 48 89 6c 24 68 c7 44 24 20 02 00 00 00 ff 15 } //2
		$a_01_2 = {62 72 62 63 6f 6e 66 69 67 2e 74 6d 70 } //1 brbconfig.tmp
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}