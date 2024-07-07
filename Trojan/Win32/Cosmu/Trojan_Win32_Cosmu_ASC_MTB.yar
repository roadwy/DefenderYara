
rule Trojan_Win32_Cosmu_ASC_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c0 3c 83 c3 c4 83 55 f0 ff 89 06 57 6a 3c ff 75 f0 53 e8 69 36 00 00 50 5b 8b 46 04 8b ca 99 57 03 d8 13 ca 6a 3c 51 } //1
		$a_01_1 = {c9 c3 56 e8 0a 37 00 00 50 5e 09 f6 75 02 5e c3 ff 74 24 08 56 e8 40 fd ff ff f7 d8 1b c0 59 f7 d0 59 23 c6 5e c3 55 54 5d 51 51 8d 45 f8 50 ff 15 8c e0 40 00 8b 45 f8 8b 4d fc 6a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}