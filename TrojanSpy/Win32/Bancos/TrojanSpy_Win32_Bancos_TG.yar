
rule TrojanSpy_Win32_Bancos_TG{
	meta:
		description = "TrojanSpy:Win32/Bancos.TG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 42 00 52 00 41 00 44 00 45 00 53 00 43 00 4f 00 2d 00 56 00 42 00 31 00 5c 00 90 02 20 5c 00 90 02 20 2e 00 76 00 62 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}