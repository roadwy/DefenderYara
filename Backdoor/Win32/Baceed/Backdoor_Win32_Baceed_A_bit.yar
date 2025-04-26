
rule Backdoor_Win32_Baceed_A_bit{
	meta:
		description = "Backdoor:Win32/Baceed.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 50 5c 37 33 34 33 38 39 33 } //1 Software\P\7343893
		$a_01_1 = {5c 4d 6f 64 75 6c 65 73 5c 42 61 73 65 43 6f 64 65 5c 4d 79 49 6e 69 2e 63 70 70 } //1 \Modules\BaseCode\MyIni.cpp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}