
rule Trojan_Win32_Zipparch_E{
	meta:
		description = "Trojan:Win32/Zipparch.E,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 52 00 54 00 4c 00 } //02 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {73 00 6d 00 73 00 5f 00 63 00 6f 00 75 00 6e 00 74 00 } //02 00  sms_count
		$a_01_2 = {2e 00 72 00 75 00 2f 00 } //01 00  .ru/
		$a_01_3 = {3f 00 66 00 69 00 6c 00 65 00 5f 00 69 00 64 00 3d 00 } //01 00  ?file_id=
		$a_01_4 = {61 00 6c 00 74 00 5f 00 70 00 61 00 79 00 } //01 00  alt_pay
		$a_01_5 = {6f 00 62 00 74 00 61 00 69 00 6e 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //00 00  obtain password
	condition:
		any of ($a_*)
 
}