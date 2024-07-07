
rule Trojan_Win32_Ninunarch_Q{
	meta:
		description = "Trojan:Win32/Ninunarch.Q,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 6e 63 2f 70 61 79 2f 3f 61 6a 61 78 3d 31 26 67 6f 3d 61 75 74 68 26 70 61 73 73 77 6f 72 64 3d 25 73 26 63 72 79 70 74 3d } //6 /sync/pay/?ajax=1&go=auth&password=%s&crypt=
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 32 52 76 64 32 35 73 62 32 46 6b 63 33 56 77 63 47 39 79 64 43 35 69 61 58 6f 3d } //1 aHR0cDovL2Rvd25sb2Fkc3VwcG9ydC5iaXo=
		$a_01_2 = {33 65 34 2f 33 65 34 2f 64 6f 33 65 34 77 6e 33 65 34 6c 6f 33 65 34 61 33 65 34 64 73 33 65 34 75 70 33 65 34 70 6f 33 65 34 72 74 33 65 34 } //1 3e4/3e4/do3e4wn3e4lo3e4a3e4ds3e4up3e4po3e4rt3e4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}