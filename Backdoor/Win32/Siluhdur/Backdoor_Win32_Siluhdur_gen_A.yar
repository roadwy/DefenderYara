
rule Backdoor_Win32_Siluhdur_gen_A{
	meta:
		description = "Backdoor:Win32/Siluhdur.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 29 bf 01 00 00 00 8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 90 01 02 ff ff 8b 55 f4 8b c6 e8 90 01 02 ff ff 47 4b 75 dc 90 00 } //1
		$a_03_1 = {83 7c c2 08 00 74 24 8b 06 8d 04 80 8b 17 8b 44 c2 08 8b 15 90 01 04 8b 52 38 e8 90 01 02 ff ff 03 05 90 01 04 a3 90 01 04 ff 06 4b 0f 85 90 01 01 ff ff ff c7 05 90 01 04 07 00 01 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}