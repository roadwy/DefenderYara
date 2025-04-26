
rule Trojan_Win64_Swrort_CG_MTB{
	meta:
		description = "Trojan:Win64/Swrort.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 fa 0c 4d 8d 40 01 48 8b cf 48 0f 45 ca 41 ff c1 42 0f b6 04 39 48 8d 51 01 41 30 40 ff 49 63 c1 48 3b c3 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}