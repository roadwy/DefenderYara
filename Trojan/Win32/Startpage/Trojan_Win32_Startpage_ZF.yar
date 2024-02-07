
rule Trojan_Win32_Startpage_ZF{
	meta:
		description = "Trojan:Win32/Startpage.ZF,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 50 61 67 65 00 00 42 75 74 74 6f 6e 00 00 c8 b7 b6 a8 00 00 00 00 23 33 32 37 37 30 00 00 c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 ca be 00 } //01 00 
		$a_01_1 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 20 4f 4b 2e } //00 00  StartServiceCtrlDispatcher OK.
	condition:
		any of ($a_*)
 
}