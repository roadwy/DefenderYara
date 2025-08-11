
rule Trojan_Win32_Alevaul_DC_MTB{
	meta:
		description = "Trojan:Win32/Alevaul.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d fc 8a 44 0e 08 88 44 3e 08 88 54 0e 08 0f b6 4c 3e 08 0f b6 c2 03 c8 81 e1 ff 00 00 80 } //10
		$a_01_1 = {8a 44 31 08 8b 4d 08 32 04 0b 88 01 41 ff 4d 0c 89 4d 08 8b 4d fc } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}