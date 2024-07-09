
rule Backdoor_Win32_Nuclear_gen_B{
	meta:
		description = "Backdoor:Win32/Nuclear.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 00 61 00 5c 00 4e 00 52 00 } //1 %a\NR
		$a_03_1 = {68 a0 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b d8 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 6a 00 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 82 00 00 00 53 e8 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}