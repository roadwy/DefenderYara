
rule Backdoor_Win32_Koutodoor_C{
	meta:
		description = "Backdoor:Win32/Koutodoor.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d 0c 8b 45 08 32 1c 02 } //1
		$a_01_1 = {83 bd 58 ff ff ff 02 75 09 83 bd 4c ff ff ff 05 73 56 8b 45 f0 83 f8 01 76 4e 83 4e 74 ff 03 c0 33 c9 a9 00 00 00 80 75 0b d1 6e 74 d1 e0 41 83 f9 20 7c ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}