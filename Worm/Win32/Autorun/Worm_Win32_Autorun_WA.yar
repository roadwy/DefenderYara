
rule Worm_Win32_Autorun_WA{
	meta:
		description = "Worm:Win32/Autorun.WA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f8 02 74 1a 56 e8 ?? ?? ff ff 83 f8 04 74 0f 56 e8 ?? ?? ff ff 83 f8 03 0f 85 ?? ?? 00 00 } //1
		$a_03_1 = {43 80 fb 7b 0f 85 ?? ff ff ff 6a 04 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}