
rule Trojan_Win64_Tedy_MKJ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 0f b7 14 49 45 8d 5a bf 41 8d 5a 20 66 41 83 fb 1a 41 0f 43 da 44 0f b6 d3 49 31 c2 4d 0f af d0 0f b6 c7 4c 31 d0 49 0f af c0 49 ff c1 4c 39 ca } //20
		$a_01_1 = {44 0f b6 c1 49 31 d0 4d 0f af c1 8a 08 48 ff c0 4c 89 c2 84 c9 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}