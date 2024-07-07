
rule Backdoor_Win32_Mecklow_A{
	meta:
		description = "Backdoor:Win32/Mecklow.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 cb 8a 5d 0a 88 4d fd 8a cb c0 e2 02 c0 e9 06 02 d1 80 e3 3f 3b 7d 14 88 5d ff } //5
		$a_01_1 = {99 b9 10 cd 0e 00 f7 f9 81 c2 10 cd 0e 00 52 } //1
		$a_03_2 = {ff ff 2a c6 85 90 01 02 ff ff 2a c6 85 90 01 02 ff ff 5b c6 85 90 01 02 ff ff 53 c6 85 90 01 02 ff ff 54 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}