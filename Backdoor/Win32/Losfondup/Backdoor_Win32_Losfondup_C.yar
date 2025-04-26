
rule Backdoor_Win32_Losfondup_C{
	meta:
		description = "Backdoor:Win32/Losfondup.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 54 1a ff 80 f2 02 88 54 18 ff 43 4e 75 e6 } //1
		$a_01_1 = {83 fe 05 7c be 0f af dd 0f af fe 03 df 81 fb b8 88 00 00 7e ae 81 fb 00 71 02 00 } //1
		$a_03_2 = {68 23 01 00 00 8d 84 24 24 01 00 00 50 57 8b 03 50 e8 ?? ?? ?? ?? c7 44 24 0c 07 00 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}