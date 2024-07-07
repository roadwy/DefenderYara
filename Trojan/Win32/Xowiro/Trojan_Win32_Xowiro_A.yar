
rule Trojan_Win32_Xowiro_A{
	meta:
		description = "Trojan:Win32/Xowiro.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d8 80 e3 fc c0 e3 90 01 01 0a 5c 0f 90 01 01 88 5d 90 01 01 8a d8 24 90 01 01 c0 e0 90 01 01 0a 04 0f c0 e3 90 01 01 0a 5c 0f 90 01 01 88 04 16 8a 45 90 01 01 46 88 04 16 8b 45 90 01 01 46 88 1c 16 83 c1 90 01 01 46 3b 08 72 90 00 } //1
		$a_03_1 = {03 45 fc 89 01 c9 c3 a1 90 01 04 b9 90 01 04 e8 90 01 04 0f b7 05 90 01 04 25 90 01 02 00 00 c3 e8 90 01 04 30 02 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}