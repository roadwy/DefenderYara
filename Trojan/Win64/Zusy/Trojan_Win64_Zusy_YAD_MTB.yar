
rule Trojan_Win64_Zusy_YAD_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 31 d0 58 44 30 14 0f 48 ff c1 48 89 c8 } //10
		$a_01_1 = {48 09 d0 48 21 d9 48 29 c8 48 31 d1 48 89 c1 48 01 c8 48 ff c9 48 ff c3 48 ff cf } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}