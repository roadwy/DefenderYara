
rule Trojan_Win32_Glupteba_DHI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 90 13 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c d9 } //1
		$a_02_1 = {c1 ee 10 81 3d ?? ?? ?? ?? cf 12 00 00 90 13 8b 8c 24 ?? ?? ?? ?? 8b c6 5e 33 cc } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}