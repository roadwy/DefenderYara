
rule Trojan_Win64_Shelm_I_MTB{
	meta:
		description = "Trojan:Win64/Shelm.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 89 45 90 01 01 48 63 45 24 48 8b 8d 90 01 04 0f b6 04 01 48 63 4d 90 01 01 0f be 4c 0d 04 33 c1 48 63 4d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}