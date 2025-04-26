
rule Trojan_Win64_DllInject_GP_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c3 48 f7 e1 48 c1 ea 04 48 6b c2 1b 48 2b c8 49 0f af cf 0f b6 44 0c 28 43 32 44 31 fc 41 88 41 ff 49 ff cc 0f 85 4b ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}