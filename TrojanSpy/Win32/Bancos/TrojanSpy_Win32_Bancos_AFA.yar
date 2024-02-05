
rule TrojanSpy_Win32_Bancos_AFA{
	meta:
		description = "TrojanSpy:Win32/Bancos.AFA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 40 61 23 6e 25 74 2a 61 23 6e 25 64 25 65 2a 72 40 2e 23 63 25 6f 25 6d } //01 00 
		$a_01_1 = {68 2a 73 23 62 25 63 2a 2e 2a 63 40 6f 23 6d } //01 00 
		$a_01_2 = {43 2a 3a 23 5c 25 42 2a 61 2a 6e 40 63 23 6f 25 42 25 72 2a 61 23 73 25 69 2a 6c 2a } //00 00 
	condition:
		any of ($a_*)
 
}