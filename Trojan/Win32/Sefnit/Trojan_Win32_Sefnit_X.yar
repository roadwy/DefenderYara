
rule Trojan_Win32_Sefnit_X{
	meta:
		description = "Trojan:Win32/Sefnit.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 83 c0 1c 50 8b 4d 0c 83 c1 14 51 8b 55 0c 83 c2 0c 52 8b 45 0c 83 c0 04 50 8b 4d 08 51 e8 90 01 04 83 c4 14 90 00 } //1
		$a_03_1 = {8b 4d 08 0f b7 51 02 83 fa 74 eb 90 14 74 90 01 01 8b 45 08 0f b7 48 02 83 f9 54 eb 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}