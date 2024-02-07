
rule Trojan_Win32_Startpage_JQ{
	meta:
		description = "Trojan:Win32/Startpage.JQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 4c 53 49 44 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 } //01 00  CLSID\{871C5380-42A0-1069-A2EA-08002B30309D}\shell\OpenHomePage\Command
		$a_02_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 73 79 73 90 02 02 6b 65 79 73 2e 64 6c 6c 22 90 00 } //01 00 
		$a_00_2 = {77 77 77 2e 68 61 6f 31 32 33 2e 63 6f 6d } //01 00  www.hao123.com
		$a_00_3 = {77 77 77 2e 39 39 36 39 2e 6e 65 74 } //00 00  www.9969.net
	condition:
		any of ($a_*)
 
}