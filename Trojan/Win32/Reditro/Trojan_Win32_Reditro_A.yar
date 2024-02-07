
rule Trojan_Win32_Reditro_A{
	meta:
		description = "Trojan:Win32/Reditro.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 74 63 68 66 69 6c 65 2e 62 61 74 } //01 00  batchfile.bat
		$a_01_1 = {65 63 68 6f 2e 32 30 39 2e 32 32 32 2e 31 33 38 2e 31 30 } //01 00  echo.209.222.138.10
		$a_01_2 = {77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 3e 3e 25 77 69 6e 64 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  www.facebook.com>>%windir%\System32\drivers\etc\hosts
		$a_01_3 = {65 63 68 6f 20 49 6e 73 74 61 6c 69 6e 67 } //00 00  echo Instaling
	condition:
		any of ($a_*)
 
}