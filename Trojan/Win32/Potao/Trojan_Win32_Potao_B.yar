
rule Trojan_Win32_Potao_B{
	meta:
		description = "Trojan:Win32/Potao.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 3d 25 73 26 63 6f 64 65 3d 25 64 } //01 00  id=%s&code=%d
		$a_03_1 = {81 7d 1c 07 20 01 00 8b f0 75 90 01 01 a1 90 00 } //01 00 
		$a_01_2 = {80 fa 0a 75 05 88 14 0e eb 0b 2a } //01 00 
		$a_03_3 = {88 07 47 4b 75 f1 90 09 09 00 6a 7a 6a 61 e8 90 00 } //01 00 
		$a_03_4 = {dd 1c 24 33 c0 ff d0 90 09 03 00 dd 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}