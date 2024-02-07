
rule Trojan_Win32_Rirlged_gen_B{
	meta:
		description = "Trojan:Win32/Rirlged.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 49 4e 4c 4f 47 4f 4e 00 00 00 00 59 6f 75 20 6c 6f 67 67 65 64 20 6f 6e 20 61 74 20 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 0a 00 54 68 65 20 68 61 73 } //01 00 
		$a_01_1 = {54 68 65 20 64 65 62 75 67 20 70 72 69 76 69 6c 65 67 65 20 68 61 73 20 62 65 65 6e 20 61 64 64 65 64 20 74 6f 20 50 61 73 73 77 6f 72 64 52 65 6d 69 6e 64 65 72 2e } //01 00  The debug privilege has been added to PasswordReminder.
		$a_02_2 = {54 72 6f 6a 61 6e 53 5f 44 4c 4c 90 03 01 01 20 2e 44 4c 4c 90 00 } //01 00 
		$a_01_3 = {73 65 76 65 6e 2d 65 6c 65 76 65 6e 20 51 51 3a 31 30 35 33 31 35 31 35 20 45 2d 6d 61 69 6c 3a 63 6e 77 61 6e 67 6d 69 6e 67 40 31 36 33 2e 63 6f 6d } //01 00  seven-eleven QQ:10531515 E-mail:cnwangming@163.com
		$a_00_4 = {21 2a 5f 2a 2d 3e 73 65 76 65 6e 2d 65 6c 65 76 65 6e 3c 2d 2a 5f 2a 21 } //00 00  !*_*->seven-eleven<-*_*!
	condition:
		any of ($a_*)
 
}