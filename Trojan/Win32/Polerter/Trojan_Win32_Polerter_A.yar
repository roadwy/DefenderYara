
rule Trojan_Win32_Polerter_A{
	meta:
		description = "Trojan:Win32/Polerter.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 65 00 72 00 74 00 65 00 72 00 33 00 43 00 6c 00 69 00 65 00 6e 00 74 00 43 00 53 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Alerter3ClientCS.Resources
		$a_01_1 = {27 00 70 00 77 00 6e 00 65 00 64 00 21 00 } //01 00  'pwned!
		$a_01_2 = {26 00 66 00 61 00 6b 00 65 00 63 00 72 00 61 00 73 00 68 00 } //01 00  &fakecrash
		$a_01_3 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2f 00 61 00 63 00 72 00 6f 00 72 00 64 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  /updater/acrord32.exe
		$a_01_4 = {2f 00 6b 00 65 00 79 00 73 00 2f 00 6b 00 65 00 79 00 73 00 2e 00 74 00 78 00 74 00 } //00 00  /keys/keys.txt
	condition:
		any of ($a_*)
 
}