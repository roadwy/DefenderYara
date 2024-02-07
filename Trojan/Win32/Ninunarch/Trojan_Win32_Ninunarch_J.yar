
rule Trojan_Win32_Ninunarch_J{
	meta:
		description = "Trojan:Win32/Ninunarch.J,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 70 61 74 63 68 66 69 6c 65 } //0a 00  vpatchfile
		$a_01_1 = {73 6d 73 39 31 31 2e 72 75 2f 74 61 72 69 66 73 2e 70 68 70 3f 63 6f 75 6e 74 72 79 5f 69 64 3d 31 26 6e 75 6d 3d 32 38 35 38 } //0a 00  sms911.ru/tarifs.php?country_id=1&num=2858
		$a_03_2 = {63 6c 6f 73 65 64 90 02 01 2d 64 65 70 66 69 6c 65 73 2e 63 6f 6d 2f 90 03 0a 0b 6d 74 78 75 70 72 2e 70 68 70 73 6d 73 2d 75 61 2e 68 74 6d 6c 90 00 } //0a 00 
		$a_03_3 = {73 77 69 64 65 72 6d 61 6c 34 2e 6e 6f 72 61 2d 3e fd 95 80 5c 73 77 69 64 65 72 6d 61 6c 90 01 70 fd 95 80 5c 61 72 63 68 73 74 61 72 74 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}