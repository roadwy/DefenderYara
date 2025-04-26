
rule Trojan_Win64_Zusy_YAM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {c8 80 00 00 48 83 ec 60 e9 } //1
		$a_03_1 = {48 8d 3f 32 c3 48 8d 3f 90 13 [0-06] 02 c3 48 8d 3f 32 c3 48 8d 3f e9 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}