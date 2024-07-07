
rule Trojan_Win32_Dursg{
	meta:
		description = "Trojan:Win32/Dursg,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {d0 89 45 e0 8b 45 e0 89 45 9c 50 8b 45 9c 89 04 24 a1 90 01 04 ff d0 89 45 e4 8b 45 e4 89 45 a0 c7 45 a4 00 00 00 00 8b 45 a4 3d 20 a1 07 00 0f 8d 90 01 02 00 00 50 c7 04 24 1c 00 00 00 e8 90 00 01 } //1
		$a_89_1 = {64 ff ff ff 8b 85 64 ff ff ff 8b 40 02 83 c0 ca 89 } //14080
	condition:
		((#a_13_0  & 1)*1+(#a_89_1  & 1)*14080) >=2
 
}