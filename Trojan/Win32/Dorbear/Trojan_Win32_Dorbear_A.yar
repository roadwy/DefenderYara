
rule Trojan_Win32_Dorbear_A{
	meta:
		description = "Trojan:Win32/Dorbear.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 61 73 73 44 73 35 42 75 39 54 65 37 } //2 passDs5Bu9Te7
		$a_01_1 = {73 73 68 2d 72 73 61 20 41 41 41 41 42 33 4e 7a 61 43 31 79 63 32 45 41 41 41 41 42 4a 51 41 41 41 51 45 41 73 72 47 6e 57 47 33 58 50 57 34 74 4f 38 74 52 4c 68 46 2b 58 51 79 75 4d 35 5a 63 4c 6c 39 74 49 73 6e 6c 4d 79 49 55 58 77 70 74 } //1 ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAsrGnWG3XPW4tO8tRLhF+XQyuM5ZcLl9tIsnlMyIUXwpt
		$a_01_2 = {39 4b 68 34 45 33 63 7a 4f 43 44 78 51 3d 3d 20 72 73 61 2d 6b 65 79 2d 32 30 31 33 31 31 32 31 } //1 9Kh4E3czOCDxQ== rsa-key-20131121
		$a_01_3 = {64 72 6f 70 62 65 61 72 } //1 dropbear
		$a_03_4 = {eb 4d 8d 45 f4 89 44 24 04 a1 90 01 04 89 04 24 e8 90 01 04 c7 44 24 04 90 01 04 89 04 24 89 c3 e8 90 01 04 85 c0 74 16 c7 44 24 04 01 00 00 00 c7 04 24 00 00 00 00 e8 90 01 04 eb 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}