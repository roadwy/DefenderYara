
rule Trojan_Win64_Cobaltstrike_AMS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 8d 20 03 00 00 48 03 f9 48 03 d9 41 ff c7 33 d2 49 8b c6 48 f7 f1 49 63 cf 48 3b c8 } //5
		$a_01_1 = {41 0f b6 0c 00 30 08 48 8d 40 01 48 83 ea 01 75 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}