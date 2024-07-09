
rule Worm_Win32_Burnwoo_B{
	meta:
		description = "Worm:Win32/Burnwoo.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bf 41 00 00 00 83 24 bd ?? ?? ?? ?? 00 47 83 ff 5a 7e f2 eb 38 e8 ?? ?? ?? ?? 83 f8 01 75 10 } //1
		$a_01_1 = {2e 25 73 2f 77 2e 70 68 70 3f 69 64 3d 25 73 } //1 .%s/w.php?id=%s
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}