
rule Trojan_Win32_Remcos_ZB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 8b c6 5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 } //01 00 
		$a_01_1 = {58 45 33 33 4d 65 73 } //00 00  XE33Mes
	condition:
		any of ($a_*)
 
}