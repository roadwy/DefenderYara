
rule Ransom_Win32_Bitpaymer{
	meta:
		description = "Ransom:Win32/Bitpaymer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //02 00  cmd.exe /c vssadmin Delete Shadows /All /Quiet
		$a_01_1 = {46 69 6c 65 73 20 73 68 6f 75 6c 64 20 68 61 76 65 20 62 6f 74 68 20 2e 4c 4f 43 4b 20 65 78 74 65 6e 73 69 6f 6e } //01 00  Files should have both .LOCK extension
		$a_01_2 = {5c 00 48 00 4f 00 57 00 5f 00 54 00 4f 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //02 00  \HOW_TO_DECRYPT.txt
		$a_01_3 = {7b 00 33 00 45 00 35 00 46 00 43 00 37 00 46 00 39 00 2d 00 39 00 41 00 35 00 31 00 2d 00 34 00 33 00 36 00 37 00 2d 00 39 00 30 00 36 00 33 00 2d 00 41 00 31 00 32 00 30 00 32 00 34 00 34 00 46 00 42 00 45 00 43 00 37 00 7d 00 } //00 00  {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
	condition:
		any of ($a_*)
 
}