
rule Backdoor_Win32_Hupigon_DE{
	meta:
		description = "Backdoor:Win32/Hupigon.DE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 61 76 65 49 6e 2d 55 6e 70 72 65 70 61 72 65 48 65 61 64 } //1 WaveIn-UnprepareHead
		$a_01_1 = {5c 53 65 78 53 6f 66 74 57 } //1 \SexSoftW
		$a_01_2 = {4b 65 79 4c 6f 67 6f 3a } //1 KeyLogo:
		$a_01_3 = {47 65 74 44 72 69 76 65 72 49 } //1 GetDriverI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}