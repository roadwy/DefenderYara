
rule Trojan_Win32_Tracur_X{
	meta:
		description = "Trojan:Win32/Tracur.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 10 30 14 31 83 c0 01 80 38 00 75 05 b8 ?? ?? ?? ?? 83 c1 01 3b cf 72 e7 8b c6 5f 5e 5b } //3
		$a_01_1 = {61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 22 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 67 72 61 6d 3d 22 } //1 advfirewall firewall add rule name="Windows Update Service" dir=in action=allow program="
		$a_01_2 = {6e 61 6d 65 3d 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 22 20 6d 6f 64 65 3d 45 4e 41 42 4c 45 20 73 63 6f 70 65 3d 41 4c 4c 20 70 72 6f 66 69 6c 65 3d 41 4c 4c } //1 name="Windows Update Service" mode=ENABLE scope=ALL profile=ALL
		$a_01_3 = {5c 6d 73 69 65 78 65 63 2e 65 78 65 } //1 \msiexec.exe
		$a_01_4 = {5c 6e 65 74 73 68 2e 65 78 65 } //1 \netsh.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}