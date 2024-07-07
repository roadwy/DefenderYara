
rule Trojan_Win32_Lethic_Q_bit{
	meta:
		description = "Trojan:Win32/Lethic.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 0f be 08 85 c9 74 58 8b 55 0c 0f be 02 0c 20 25 ff 00 00 00 8b 4d fc 33 c8 89 4d fc 8b 55 0c 83 c2 01 89 55 0c c7 45 f8 00 00 00 00 eb 09 } //1
		$a_03_1 = {8b 4d fc d1 e9 8b 55 fc 83 e2 01 a1 90 01 04 8b 80 90 01 04 0f af c2 33 c8 89 4d fc eb d1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}