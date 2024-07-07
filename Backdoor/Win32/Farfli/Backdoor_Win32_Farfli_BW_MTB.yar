
rule Backdoor_Win32_Farfli_BW_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 90 01 01 80 c2 90 01 01 88 14 01 41 3b ce 7c 90 00 } //4
		$a_01_1 = {50 6c 75 67 69 6e 4d 65 } //1 PluginMe
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}