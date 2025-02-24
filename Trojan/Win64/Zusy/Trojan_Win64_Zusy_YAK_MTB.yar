
rule Trojan_Win64_Zusy_YAK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 48 8d 3f 48 8d 3f 02 c3 90 13 48 8d 3f 32 c3 48 8d 3f 48 8d 3f 90 13 48 8d 3f 2a c3 48 8d 3f 48 8d 3f 90 13 48 8d 3f 48 8d 3f 32 c3 48 8d 3f e9 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}