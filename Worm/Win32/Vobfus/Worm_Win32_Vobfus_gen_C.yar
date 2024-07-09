
rule Worm_Win32_Vobfus_gen_C{
	meta:
		description = "Worm:Win32/Vobfus.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c ?? ff 0b ?? 00 0c 00 31 ?? ff } //1
		$a_03_1 = {f3 00 01 c1 e7 04 ?? ff 9d fb 12 fc 0d } //1
		$a_03_2 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}