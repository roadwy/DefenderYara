
rule Backdoor_Win32_PipeMagic_PA_MTB{
	meta:
		description = "Backdoor:Win32/PipeMagic.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 00 75 00 63 00 6b 00 69 00 74 00 } //1 fuckit
		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 31 2e 25 73 } //3 \\.\pipe\1.%s
		$a_03_2 = {99 b9 ff 00 00 00 f7 f9 88 96 ?? ?? ?? ?? 46 83 fe 10 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_03_2  & 1)*1) >=5
 
}