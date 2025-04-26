
rule Trojan_Win64_CryptInject_YAZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c1 8b 55 ea 0f b6 85 ?? ?? ?? ?? 48 89 9d ?? ?? ?? ?? 4c 29 fa 48 8d 75 ba 0b 85 ?? ?? ?? ?? 48 81 ca ?? ?? ?? ?? 49 89 ca } //10
		$a_01_1 = {44 30 27 53 41 56 41 57 56 57 55 } //1 D0'SAVAWVWU
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}