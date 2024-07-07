
rule Worm_Win32_Xema_gen_A{
	meta:
		description = "Worm:Win32/Xema.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 52 65 63 79 63 6c 65 90 01 01 5c 90 00 } //10
		$a_00_1 = {25 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 %sautorun.inf
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}