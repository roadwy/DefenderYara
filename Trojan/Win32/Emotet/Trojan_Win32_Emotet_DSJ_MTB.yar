
rule Trojan_Win32_Emotet_DSJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_1 = {49 57 68 7a 7a 55 65 50 6c 38 6d 64 50 42 30 72 6d 4a 69 49 53 41 71 31 69 } //1 IWhzzUePl8mdPB0rmJiISAq1i
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}