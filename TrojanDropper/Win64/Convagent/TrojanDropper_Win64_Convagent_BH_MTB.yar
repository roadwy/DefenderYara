
rule TrojanDropper_Win64_Convagent_BH_MTB{
	meta:
		description = "TrojanDropper:Win64/Convagent.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 c2 48 8d 4d cf 48 03 c8 8d 42 13 ff c2 30 01 83 fa 18 72 } //1
		$a_01_1 = {48 63 c8 48 8d 54 24 40 48 8d 14 4a 41 8d 0c 01 ff c0 66 31 0a 83 f8 13 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}