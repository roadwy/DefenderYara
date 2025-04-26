
rule Backdoor_Win32_Unowvee_LOWFIA{
	meta:
		description = "Backdoor:Win32/Unowvee.LOWFIA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 2e 58 66 [0-0a] 6a 70 58 66 [0-0a] 6a 6e 58 66 [0-0a] 6a 67 } //1
		$a_03_1 = {8a 14 07 8b cf 83 e1 01 80 c2 05 32 54 ?? ?? 88 14 07 47 3b fe 7c } //1
		$a_03_2 = {6e 6e 6a 6a c7 [0-0a] 6a 68 62 6e c7 [0-0a] 4b 76 30 30 c7 [0-0a] 6d 35 47 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}