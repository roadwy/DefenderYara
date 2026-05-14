
rule Trojan_Win64_Rhadamanthys_NTH_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 44 0f df ee 66 44 0f eb ea 66 0f db f8 66 0f eb fd 66 0f 6f d7 } //2
		$a_01_1 = {66 41 0f db d7 66 45 0f fc dc 66 45 0f db ef 66 45 0f df fb 66 45 0f eb fd 66 0f db c2 66 41 0f df d7 66 0f eb c2 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}