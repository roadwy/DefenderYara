
rule Trojan_Win32_Keyloggger_A{
	meta:
		description = "Trojan:Win32/Keyloggger.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 43 44 25 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 20 2f 59 20 2f 68 20 2f 6b 20 2f 72 20 25 57 49 4e 44 49 52 25 } //01 00  %CD%\autorun.inf /Y /h /k /r %WINDIR%
		$a_00_1 = {5b 2a 5d 4b 65 79 6c 6f 67 } //01 00  [*]Keylog
		$a_03_2 = {83 d8 03 b9 20 00 00 00 2d 90 01 04 66 89 88 90 01 04 bb 5b 2a 5d 20 bf 56 65 6e 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}