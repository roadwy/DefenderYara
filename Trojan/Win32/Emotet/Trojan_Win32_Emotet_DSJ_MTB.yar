
rule Trojan_Win32_Emotet_DSJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 45 0f b6 94 14 90 01 04 30 55 90 00 } //01 00 
		$a_81_1 = {49 57 68 7a 7a 55 65 50 6c 38 6d 64 50 42 30 72 6d 4a 69 49 53 41 71 31 69 } //00 00  IWhzzUePl8mdPB0rmJiISAq1i
	condition:
		any of ($a_*)
 
}