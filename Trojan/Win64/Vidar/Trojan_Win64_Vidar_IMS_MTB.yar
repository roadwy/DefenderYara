
rule Trojan_Win64_Vidar_IMS_MTB{
	meta:
		description = "Trojan:Win64/Vidar.IMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c1 49 f7 f2 42 0f b6 04 1a 41 30 04 09 48 ff c1 49 3b c8 72 e7 } //5
		$a_01_1 = {33 d2 48 8b c7 49 f7 f1 42 0f b6 04 12 30 04 0f 48 ff c7 49 3b f8 72 e8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}