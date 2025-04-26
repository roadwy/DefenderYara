
rule Worm_Win32_Esfury_T{
	meta:
		description = "Worm:Win32/Esfury.T,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f4 11 fc 0d 0a ?? ?? ?? ?? 3c f5 00 00 00 00 f5 00 00 00 00 f4 00 fc 0d f4 56 fc 0d 0a ?? ?? ?? ?? 3c f5 00 00 00 00 f5 02 00 00 00 f4 00 fc 0d f4 56 fc 0d } //1
		$a_03_1 = {f4 02 eb b3 fb e6 ea f4 01 eb c8 35 ?? ff 1c 92 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}