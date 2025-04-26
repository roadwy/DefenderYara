
rule Trojan_Win32_RedLine_RDCG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 dc 0f b6 4d ee 8b 45 e8 33 d2 f7 75 e4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ef } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}