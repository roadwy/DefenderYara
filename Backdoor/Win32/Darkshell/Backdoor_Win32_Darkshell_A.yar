
rule Backdoor_Win32_Darkshell_A{
	meta:
		description = "Backdoor:Win32/Darkshell.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b e1 22 00 0f 85 ?? ?? 00 00 83 65 ?? 00 6a 04 6a 04 } //1
		$a_03_1 = {83 4d fc ff 8b 1b [0-03] a1 ?? ?? ?? ?? 39 58 ?? 77 ?? c7 45 ?? 0d 00 00 c0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}