
rule Trojan_Win32_Trickbot_SP_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 [0-03] 00 00 00 00 00 01 05 [0-03] 00 8b 0d [0-03] 00 8b 15 [0-03] 00 89 11 } //1
		$a_02_1 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d [0-03] 00 00 8b 4d 08 89 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}