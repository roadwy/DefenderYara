
rule Trojan_Win32_Emotet_RAC_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RAC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 bb ?? ?? ?? ?? f7 fb 45 0f b6 c2 8a 0c 08 8b 44 24 ?? 30 4c 28 ?? 3b 6c 24 ?? 7c } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}