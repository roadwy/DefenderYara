
rule Backdoor_Win32_CryptInject_MBHG_MTB{
	meta:
		description = "Backdoor:Win32/CryptInject.MBHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 ff cc 31 00 14 7c 85 a7 } //1
		$a_01_1 = {c4 dd 4e 00 df f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 4c d6 4e 00 00 d3 4e 00 28 32 40 00 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}