
rule TrojanSpy_Win32_Bancos_XT{
	meta:
		description = "TrojanSpy:Win32/Bancos.XT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 45 78 70 6c 6f 72 65 00 00 00 00 ff ff ff ff 11 00 00 00 70 6f 72 74 61 6c 2e 6c 61 63 61 69 78 61 2e 65 73 00 00 00 ff ff ff ff 07 00 00 00 41 50 50 44 41 54 41 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 08 00 00 00 5c 62 6b 31 2e 6c 6f 67 00 00 00 00 ff ff ff ff 01 00 00 00 31 00 00 00 ff ff ff ff 14 00 00 00 77 77 77 2e 63 61 69 78 61 70 65 6e 65 64 65 73 2e 63 6f 6d 00 00 00 00 ff ff ff ff 08 00 00 00 5c 62 6b 32 2e 6c 6f 67 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}