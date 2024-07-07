
rule Trojan_Win32_Dishigy_H{
	meta:
		description = "Trojan:Win32/Dishigy.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //1
		$a_00_1 = {74 6b 65 6b 71 65 59 } //1 tkekqeY
		$a_00_2 = {6c 6f 67 69 6e 3d 5b 31 30 30 30 5d 26 70 61 73 73 3d 5b 31 30 30 30 5d 26 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d 26 6c 6f 67 3d 5b 35 30 5d 26 70 61 73 73 77 72 64 3d 5b 35 30 5d 26 75 73 65 72 } //1 login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user
		$a_00_3 = {73 79 73 74 65 6d 73 6b 65 79 2e 69 6e 69 } //1 systemskey.ini
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}