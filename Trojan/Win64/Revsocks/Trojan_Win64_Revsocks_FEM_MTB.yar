
rule Trojan_Win64_Revsocks_FEM_MTB{
	meta:
		description = "Trojan:Win64/Revsocks.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 c0 e8 04 45 0f b6 c0 4c 8d 15 f8 8e 0c 00 47 0f b6 04 02 48 39 df 73 3a 44 88 04 38 4c 8d 47 01 41 83 e1 0f 47 0f b6 0c 11 4c 39 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}