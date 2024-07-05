
rule Trojan_Win64_CryptInject_GIT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c2 41 32 01 ff c9 88 02 74 22 41 0f b7 c2 66 c1 e8 08 41 32 41 01 88 42 01 8d 41 ff 85 c0 74 0c } //00 00 
	condition:
		any of ($a_*)
 
}