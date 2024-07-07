
rule Backdoor_Win32_Haxdoor_gen_D{
	meta:
		description = "Backdoor:Win32/Haxdoor.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 f3 ff 35 04 10 40 00 81 2c 24 90 01 04 ff 24 24 90 00 } //1
		$a_03_1 = {75 f2 ff 35 04 10 40 00 81 2c 24 90 01 04 ff 0c 24 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}