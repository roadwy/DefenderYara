
rule Worm_Win32_Autorun_XI{
	meta:
		description = "Worm:Win32/Autorun.XI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 00 6e 00 69 00 2e 00 6e 00 75 00 72 00 6f 00 74 00 75 00 61 00 } //1 fni.nurotua
		$a_00_1 = {5d 00 6e 00 75 00 72 00 6f 00 74 00 75 00 41 00 5b 00 } //1 ]nurotuA[
		$a_01_2 = {28 14 ff 61 00 04 48 ff 28 24 ff 7a 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}