
rule Worm_Win32_Catinea_A{
	meta:
		description = "Worm:Win32/Catinea.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 43 04 02 74 16 8b 03 83 f8 06 74 05 83 f8 01 75 0a 8d 43 f8 50 e8 } //01 00 
		$a_01_1 = {53 6a 5a 8d 45 88 50 68 68 ae 41 00 ff 75 84 ff d7 } //01 00 
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 20 61 20 2d 69 6e 75 6c 20 2d 79 20 2d 65 70 32 20 2d 6f 2b 20 20 22 25 73 22 20 22 25 73 } //01 00  cmd.exe /c %s a -inul -y -ep2 -o+  "%s" "%s
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 20 76 62 20 2d 69 62 63 6b 20 20 2d 79 20 2d 70 2d 20 22 25 73 22 20 3e 22 25 73 } //00 00  cmd.exe /c %s vb -ibck  -y -p- "%s" >"%s
	condition:
		any of ($a_*)
 
}