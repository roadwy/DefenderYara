
rule Trojan_Win32_Malgent_BD_MTB{
	meta:
		description = "Trojan:Win32/Malgent.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 18 33 d1 33 da 81 c1 dc 5e 2c 00 89 18 83 c0 04 8d 1c 06 3b df 76 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}