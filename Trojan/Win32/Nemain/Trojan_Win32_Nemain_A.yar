
rule Trojan_Win32_Nemain_A{
	meta:
		description = "Trojan:Win32/Nemain.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 72 65 61 64 5f 69 2e 70 68 70 } //1 /bin/read_i.php
		$a_03_1 = {33 36 30 74 72 61 79 2e 65 78 65 [0-02] 6d 73 73 65 63 65 73 2e 65 78 65 [0-02] 75 69 57 69 6e 4d 67 72 2e 65 78 65 } //1
		$a_01_2 = {25 73 3f 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 73 26 61 34 3d 25 73 } //1 %s?a1=%s&a2=%s&a3=%s&a4=%s
		$a_01_3 = {55 53 42 20 43 6f 75 6e 74 3a 20 25 64 3c 62 72 3e } //1 USB Count: %d<br>
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}