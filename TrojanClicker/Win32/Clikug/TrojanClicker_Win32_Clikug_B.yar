
rule TrojanClicker_Win32_Clikug_B{
	meta:
		description = "TrojanClicker:Win32/Clikug.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 00 79 00 70 00 65 00 72 00 20 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //2 Hyper Browser
		$a_01_1 = {43 68 72 6f 6d 65 20 57 6f 72 6b 65 72 20 46 61 69 6c 65 64 2c 20 25 73 } //1 Chrome Worker Failed, %s
		$a_01_2 = {43 6c 69 63 6b 20 54 6f 20 78 3a 20 25 64 20 79 3a 20 25 64 } //2 Click To x: %d y: %d
		$a_01_3 = {25 73 2f 73 74 61 74 2f 75 69 64 2f 25 73 2f 73 69 64 2f 25 64 2f 61 2f 25 73 2f } //2 %s/stat/uid/%s/sid/%d/a/%s/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=7
 
}