
rule Trojan_Win64_Vidar_GVF_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 ff c2 49 63 ca 0f b6 44 0c 60 88 44 1c 60 } //1
		$a_01_1 = {43 32 1c 2b 43 88 1c 23 49 ff c3 4d 3b df 0f 82 90 fc ff ff } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}