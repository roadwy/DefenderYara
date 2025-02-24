
rule Trojan_Win64_Cryptinject_YBE_MTB{
	meta:
		description = "Trojan:Win64/Cryptinject.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0d 87 43 32 44 0b ?? 41 88 41 fb 41 8d 42 ff 48 63 c8 48 8b c3 48 f7 e1 } //10
		$a_03_1 = {48 2b c8 49 0f af cc 0f b6 44 0d ?? 42 32 44 0e fb 41 88 41 fd 41 8d 42 01 48 63 c8 48 8b c3 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}