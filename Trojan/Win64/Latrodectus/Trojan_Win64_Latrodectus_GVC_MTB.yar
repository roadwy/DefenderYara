
rule Trojan_Win64_Latrodectus_GVC_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f c3 45 8a 14 11 66 0f 6d cf 66 0f 6f cb } //2
		$a_01_1 = {66 0f 6c ca 44 30 14 0f 66 0f 6f c1 66 0f dd e6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}