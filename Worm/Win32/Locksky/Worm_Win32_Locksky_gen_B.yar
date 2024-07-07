
rule Worm_Win32_Locksky_gen_B{
	meta:
		description = "Worm:Win32/Locksky.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7b 00 44 00 44 00 33 00 42 00 37 00 46 00 41 00 38 00 2d 00 33 00 42 00 45 00 38 00 2d 00 34 00 39 00 30 00 66 00 2d 00 38 00 45 00 39 00 44 00 2d 00 30 00 30 00 33 00 36 00 43 00 45 00 37 00 35 00 33 00 36 00 37 00 39 00 7d 00 } //4 Global\{DD3B7FA8-3BE8-490f-8E9D-0036CE753679}
		$a_01_1 = {6d 61 69 6c 65 72 20 66 61 69 6c 20 6c 6f 67 20 2c 68 61 72 64 77 61 72 65 20 69 64 3a 20 25 6c 75 2c 69 6e 73 74 63 61 74 20 76 65 72 73 69 6f 6e 3a 20 25 6c 75 2e 25 6c 75 } //3 mailer fail log ,hardware id: %lu,instcat version: %lu.%lu
		$a_01_2 = {2f 6c 6f 67 32 2e 70 68 70 3f 68 69 64 3d 25 6c 75 } //3 /log2.php?hid=%lu
	condition:
		((#a_00_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=10
 
}