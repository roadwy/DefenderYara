
rule Trojan_Win32_Trickbot_NBM_ST{
	meta:
		description = "Trojan:Win32/Trickbot.NBM!ST,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 ?? ?? ?? ?? 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}