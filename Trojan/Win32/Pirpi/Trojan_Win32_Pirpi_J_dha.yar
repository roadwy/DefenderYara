
rule Trojan_Win32_Pirpi_J_dha{
	meta:
		description = "Trojan:Win32/Pirpi.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f4 5e b9 22 00 00 00 33 c0 8d bd 78 ff ff ff f3 ab 8b 45 08 33 c9 66 8b 0c 45 ?? ?? ?? ?? 33 d2 66 8b 15 ?? ?? ?? ?? 33 ca 8b 45 08 33 d2 66 8b 14 45 } //1
		$a_02_1 = {8b d8 83 fb ff 74 ?? 8d 84 24 98 00 00 00 50 53 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b 35 ?? ?? ?? ?? 8d 4c 24 10 8d 54 24 0c 51 52 6a 4d e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}