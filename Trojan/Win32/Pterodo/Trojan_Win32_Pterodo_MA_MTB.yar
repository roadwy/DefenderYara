
rule Trojan_Win32_Pterodo_MA_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 05 20 90 01 04 b6 10 8b 45 e4 83 c0 01 0f b6 80 90 01 04 31 c2 8b 45 e4 05 90 01 04 88 10 83 45 e4 01 eb 90 00 } //1
		$a_00_1 = {8d 95 18 fa ff ff 89 54 24 24 8d 95 28 fa ff ff 89 54 24 20 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 89 44 24 04 c7 04 24 00 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}