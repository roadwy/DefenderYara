
rule Backdoor_Win32_Detarmal_A{
	meta:
		description = "Backdoor:Win32/Detarmal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 3b 6d 72 74 64 0f 85 } //1
		$a_03_1 = {83 f8 46 0f 8f ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 83 f8 2f 7f ?? 74 ?? 83 e8 28 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}