
rule Trojan_Win32_Dulkit_A{
	meta:
		description = "Trojan:Win32/Dulkit.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e } //1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.
		$a_01_1 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 74 5f 64 72 69 76 65 72 2e 65 78 65 00 } //1
		$a_01_2 = {2f 73 74 61 74 2e 70 68 70 3f 75 3d 64 69 6d 61 26 6b 3d 4f 6b } //1 /stat.php?u=dima&k=Ok
		$a_01_3 = {2f 64 72 69 76 65 72 2e 70 68 70 3f 63 3d } //1 /driver.php?c=
		$a_01_4 = {2f 64 72 69 76 65 72 2e 70 68 70 3f 75 3d } //1 /driver.php?u=
		$a_01_5 = {41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}