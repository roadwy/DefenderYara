
rule Backdoor_Win32_Firwat_A{
	meta:
		description = "Backdoor:Win32/Firwat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 c8 2c 41 3c 01 0f 97 c2 31 c0 80 f9 61 0f 95 c0 85 c2 74 15 80 f9 62 74 10 89 3c 24 e8 } //01 00 
		$a_01_1 = {5b 75 73 62 2b 5d 20 69 6e 66 65 63 74 65 64 20 64 72 69 76 65 3a 20 25 73 } //01 00  [usb+] infected drive: %s
		$a_01_2 = {5c 66 69 72 65 00 5c 77 61 74 65 72 00 } //01 00 
		$a_01_3 = {4e 41 4d 45 4c 45 53 53 42 4f 54 5f 56 } //01 00  NAMELESSBOT_V
		$a_01_4 = {5b 73 73 79 6e 5d 20 66 6c 6f 6f 64 69 6e 67 3a 20 } //00 00  [ssyn] flooding: 
	condition:
		any of ($a_*)
 
}