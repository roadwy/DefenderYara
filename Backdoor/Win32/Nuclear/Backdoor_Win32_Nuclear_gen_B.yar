
rule Backdoor_Win32_Nuclear_gen_B{
	meta:
		description = "Backdoor:Win32/Nuclear.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 61 00 5c 00 4e 00 52 00 } //0a 00  %a\NR
		$a_03_1 = {68 a0 00 00 00 8b 45 fc e8 90 01 04 8b d8 53 e8 90 01 04 53 e8 90 01 04 6a 00 53 68 90 01 04 e8 90 01 04 68 82 00 00 00 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}