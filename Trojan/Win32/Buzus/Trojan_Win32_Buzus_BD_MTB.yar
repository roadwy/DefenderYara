
rule Trojan_Win32_Buzus_BD_MTB{
	meta:
		description = "Trojan:Win32/Buzus.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 10 a7 38 08 00 2b 33 71 b5 94 90 3c 61 4f 3c 6f 41 a8 48 2c a5 5b ef bf 92 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 } //2
		$a_01_1 = {34 00 37 00 34 00 32 00 35 00 34 00 34 00 34 00 34 00 39 00 35 00 33 00 00 00 5f 5f 76 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}