
rule Trojan_Win32_Trickbot_PA_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.PA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 68 60 11 00 00 6a 00 ff d3 68 60 11 00 00 68 ?? ?? ?? 00 50 e8 ?? ?? ff ff 8d 54 24 0c 52 56 6a 10 68 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}