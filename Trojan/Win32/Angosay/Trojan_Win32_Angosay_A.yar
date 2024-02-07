
rule Trojan_Win32_Angosay_A{
	meta:
		description = "Trojan:Win32/Angosay.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 14 00 "
		
	strings :
		$a_02_0 = {52 54 4d 5f 49 6d 61 67 65 4d 6f 64 52 65 63 2e 64 6c 6c 90 02 10 52 48 42 69 6e 64 65 72 5f 5f 53 68 69 6d 45 78 65 4d 61 69 6e 90 00 } //0a 00 
		$a_00_1 = {57 69 6e 64 6f 77 73 2e 55 49 2e 58 61 6d 6c 2e } //01 00  Windows.UI.Xaml.
		$a_00_2 = {52 65 61 64 41 6c 6c 42 79 74 65 73 } //01 00  ReadAllBytes
		$a_00_3 = {45 6e 63 72 79 70 74 4b 65 79 } //01 00  EncryptKey
		$a_00_4 = {57 72 69 74 65 41 6c 6c 42 79 74 65 } //01 00  WriteAllByte
		$a_00_5 = {67 65 74 5f 46 69 72 73 74 4e 61 6d 65 } //01 00  get_FirstName
		$a_00_6 = {67 65 74 5f 4c 61 73 74 4e 61 6d 65 } //01 00  get_LastName
		$a_00_7 = {5c 00 22 00 75 00 72 00 6c 00 5c 00 22 00 5c 00 73 00 2a 00 3a 00 5c 00 73 00 2a 00 5c 00 22 00 28 00 68 00 74 00 74 00 70 00 5b 00 } //01 00  \"url\"\s*:\s*\"(http[
		$a_00_8 = {3a 00 38 00 30 00 38 00 30 00 2f 00 67 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 } //00 00  :8080/getlogo
		$a_00_9 = {5d 04 00 00 70 b1 03 80 5c 21 00 00 71 b1 } //03 80 
	condition:
		any of ($a_*)
 
}