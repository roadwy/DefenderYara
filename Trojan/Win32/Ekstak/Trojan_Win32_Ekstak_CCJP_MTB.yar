
rule Trojan_Win32_Ekstak_CCJP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 00 8a 0d ?? f0 65 00 32 c8 56 88 0d ?? f0 65 00 8a 0d ?? f0 65 00 80 c9 08 8b b4 24 b8 00 00 00 c0 e9 03 81 e1 ff } //2
		$a_03_1 = {89 45 fc 8a 0d ?? f0 65 00 32 0d ?? f0 65 00 88 0d ?? f0 65 00 33 d2 8a 15 ?? f0 65 00 c1 fa 03 83 ca 01 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}