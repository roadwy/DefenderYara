
rule Trojan_Win32_Mitav_A{
	meta:
		description = "Trojan:Win32/Mitav.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 66 6f 2e 70 68 70 3f 69 64 64 3d } //1 /info.php?idd=
		$a_03_1 = {2d 72 20 22 25 31 22 20 25 2a 90 02 02 45 4c 45 56 41 54 45 43 52 45 41 54 45 50 52 4f 43 45 53 53 00 90 00 } //1
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}