
rule Trojan_Win32_Bepdro_A{
	meta:
		description = "Trojan:Win32/Bepdro.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 66 75 63 6b 00 00 00 ff ff ff ff 2d 00 00 00 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 00 00 ff ff ff ff 22 00 00 00 25 57 69 6e 44 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bepdro_A_2{
	meta:
		description = "Trojan:Win32/Bepdro.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {2d 66 75 63 6b } //01 00  -fuck
		$a_01_3 = {73 61 66 65 6d 6f 6e 2e 64 6c 6c } //01 00  safemon.dll
		$a_01_4 = {69 65 62 75 64 64 79 2e 64 6c 6c } //01 00  iebuddy.dll
		$a_01_5 = {52 61 76 4d 6f 6e 2e 65 78 65 2c 61 76 70 2e 65 78 65 2c 33 36 30 74 72 61 79 2e 65 78 65 2c 52 53 54 72 61 79 2e 65 78 65 } //01 00  RavMon.exe,avp.exe,360tray.exe,RSTray.exe
		$a_01_6 = {64 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 } //01 00  drivers\Beep.sys
		$a_01_7 = {69 66 20 65 78 69 73 74 } //01 00  if exist
		$a_01_8 = {77 65 30 34 77 65 30 35 } //00 00  we04we05
	condition:
		any of ($a_*)
 
}