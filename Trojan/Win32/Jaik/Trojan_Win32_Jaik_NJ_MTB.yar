
rule Trojan_Win32_Jaik_NJ_MTB{
	meta:
		description = "Trojan:Win32/Jaik.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 8d 14 00 8b 45 e4 01 d0 0f b7 00 66 83 f8 5c 75 ?? 8b 45 e0 8d 14 00 8b 45 e4 01 d0 } //3
		$a_01_1 = {83 ec 28 c7 45 d8 2a 00 00 00 8b 55 d8 8b 45 c8 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 10 00 00 89 54 24 08 c7 44 24 04 00 00 00 00 89 04 24 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}