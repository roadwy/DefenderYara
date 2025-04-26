
rule TrojanProxy_Win32_Cahecon_A{
	meta:
		description = "TrojanProxy:Win32/Cahecon.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 74 65 6d 70 25 5c 73 65 6e 64 25 5f 6c 5f 25 2e 76 62 73 } //1 %temp%\send%_l_%.vbs
		$a_03_1 = {75 6f 6c 2e 63 6f 6e 68 65 63 61 61 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 62 6c 61 63 6b 2f 3f [0-05] 74 69 70 6f 3d 61 6c 69 76 65 69 26 63 6c 69 65 6e 74 65 3d 74 65 73 74 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}