
rule Trojan_Win32_Zusy_MBWQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 58 53 56 57 89 65 e8 ff 15 ?? 83 63 00 33 d2 8a d4 89 15 44 0d 64 00 8b c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_MBWQ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 4c 00 33 d2 8a d4 89 15 90 fb 4c 00 8b c8 81 e1 ff 00 00 00 89 0d 8c fb 4c 00 c1 e1 08 03 ca 89 0d 88 fb 4c } //2
		$a_03_1 = {55 8b ec 6a ff 68 ?? 92 4c 00 68 ?? 4c 4c 00 64 a1 00 00 00 00 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}