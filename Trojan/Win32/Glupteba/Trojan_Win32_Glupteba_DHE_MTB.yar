
rule Trojan_Win32_Glupteba_DHE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 85 ff 7e ?? 81 ff ?? ?? ?? ?? 90 13 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c df } //1
		$a_02_1 = {83 ec 50 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 90 13 c1 ee 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 90 13 8b c6 25 ?? ?? ?? ?? 5e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}