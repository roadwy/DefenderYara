
rule Trojan_Win64_Latrodectus_BJ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 0f fd c2 44 30 14 0f } //2
		$a_01_1 = {66 0f f9 d0 45 8a 14 11 } //1
		$a_01_2 = {66 0f 6f cb 66 0f 6f c3 49 f7 f3 } //1
		$a_01_3 = {66 0f 6f c8 48 31 d2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}