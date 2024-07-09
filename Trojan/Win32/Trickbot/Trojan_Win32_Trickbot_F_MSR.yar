
rule Trojan_Win32_Trickbot_F_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.F!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {45 33 c9 81 e5 ?? ?? ?? ?? 33 c0 8a 4c 2c 10 03 d9 81 e3 ?? ?? ?? ?? 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}