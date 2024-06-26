
rule PWS_Win32_KBoy_A{
	meta:
		description = "PWS:Win32/KBoy.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 20 32 30 31 } //01 00  Proxy 201
		$a_01_1 = {49 4a 55 44 48 53 44 4a 46 4b 4a 44 45 } //01 00  IJUDHSDJFKJDE
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 20 64 65 76 69 63 65 20 61 6e 64 20 44 72 69 76 65 72 73 20 55 70 64 61 74 65 } //01 00  Microsoft device and Drivers Update
		$a_01_3 = {24 73 79 73 69 6e 66 6f 24 } //01 00  $sysinfo$
		$a_01_4 = {24 73 68 65 6c 6c 24 } //01 00  $shell$
		$a_01_5 = {24 66 69 6c 65 55 70 6c 6f 61 64 24 } //01 00  $fileUpload$
		$a_03_6 = {43 52 45 44 52 49 56 45 52 90 02 01 2e 64 6c 6c 90 00 } //01 00 
		$a_01_7 = {20 77 65 62 73 69 74 65 20 3d 20 25 73 } //00 00   website = %s
	condition:
		any of ($a_*)
 
}