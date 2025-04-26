
rule Trojan_Win64_DllInject_GV_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 49 0f af cf 0f b6 44 0d 97 43 32 44 31 fc 41 88 41 ff 49 ff cc 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}