
rule Trojan_Win32_Killav_DI{
	meta:
		description = "Trojan:Win32/Killav.DI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 73 63 20 63 6f 6e 66 69 67 20 65 6b 72 6e 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //01 00  cmd /c sc config ekrn start= disabled
		$a_01_1 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d 20 65 } //01 00  /c taskkill.exe /im e
		$a_01_2 = {25 73 25 64 74 65 73 74 2e 64 6c 6c } //00 00  %s%dtest.dll
	condition:
		any of ($a_*)
 
}