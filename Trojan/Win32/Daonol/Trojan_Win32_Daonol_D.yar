
rule Trojan_Win32_Daonol_D{
	meta:
		description = "Trojan:Win32/Daonol.D,SIGNATURE_TYPE_PEHSTR,08 00 08 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 73 71 6c 73 6f 64 62 63 2e 63 68 6d } //02 00  C:\WINDOWS\SYSTEM32\sqlsodbc.chm
		$a_01_1 = {76 69 72 75 74 7e } //02 00  virut~
		$a_01_2 = {46 4f 4f 42 41 52 } //01 00  FOOBAR
		$a_01_3 = {6d 69 65 6b 69 65 6d 6f 65 73 } //01 00  miekiemoes
		$a_01_4 = {46 6f 6f 42 61 72 2e 6c 6f 63 61 6c 2e 68 6f 73 74 } //01 00  FooBar.local.host
		$a_01_5 = {6c 6f 63 61 6c 2e 66 6f 6f 2e 63 6f 6d } //01 00  local.foo.com
		$a_01_6 = {66 6f 6f 62 61 72 67 } //00 00  foobarg
	condition:
		any of ($a_*)
 
}