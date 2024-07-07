
rule TrojanProxy_Win32_Dorando_gen_B{
	meta:
		description = "TrojanProxy:Win32/Dorando.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 65 73 73 65 6e 67 65 72 00 00 00 47 6c 6f 62 61 6c 5c } //1
		$a_01_1 = {61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 6d 65 73 73 65 6e 67 65 72 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 54 43 50 20 6c 6f 63 61 6c 70 6f 72 74 3d 25 64 } //1 add rule name=messenger dir=in action=allow protocol=TCP localport=%d
		$a_01_2 = {70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 25 64 20 6d 65 73 73 65 6e 67 65 72 20 45 4e 41 42 4c 45 20 41 4c 4c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}