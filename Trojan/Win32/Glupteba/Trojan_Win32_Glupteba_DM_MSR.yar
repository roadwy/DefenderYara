
rule Trojan_Win32_Glupteba_DM_MSR{
	meta:
		description = "Trojan:Win32/Glupteba.DM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e8 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 33 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? 91 05 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}