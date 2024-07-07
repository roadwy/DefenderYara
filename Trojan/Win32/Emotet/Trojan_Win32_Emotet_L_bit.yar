
rule Trojan_Win32_Emotet_L_bit{
	meta:
		description = "Trojan:Win32/Emotet.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 03 45 e8 8b 4d f8 03 4d e8 8a 11 88 10 eb dd } //1
		$a_01_1 = {8b 4d dc c1 e1 04 03 4d e8 8b 55 dc 03 55 f0 33 ca 8b 45 dc c1 e8 05 03 45 ec 33 c8 8b 55 f4 2b d1 89 55 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}