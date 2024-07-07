
rule Worm_Win32_Vobfus_gen_E{
	meta:
		description = "Worm:Win32/Vobfus.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {04 50 ff f3 c3 00 fc 0d } //2
		$a_01_1 = {3c 00 00 00 59 01 00 00 04 29 00 00 1f 1d } //1
		$a_01_2 = {3c 00 00 00 59 01 00 00 c0 30 00 00 c8 19 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}