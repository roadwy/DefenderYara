
rule Trojan_Win32_Qbot_AG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 58 4c 35 35 00 } //01 00  堀㕌5
		$a_01_1 = {00 52 73 63 5f 61 74 74 61 63 68 5f 64 61 74 61 62 61 73 65 00 } //01 00 
		$a_01_2 = {00 52 73 63 5f 70 72 65 70 61 72 65 5f 74 72 61 6e 73 61 63 74 69 6f 6e 00 } //01 00 
		$a_01_3 = {00 52 64 73 5f 5f 74 72 61 6e 73 61 63 74 69 6f 6e 5f 63 6c 65 61 6e 75 70 00 } //00 00  刀獤彟牴湡慳瑣潩彮汣慥畮p
	condition:
		any of ($a_*)
 
}