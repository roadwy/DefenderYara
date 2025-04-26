
rule Trojan_Win32_Staser_RE_MTB{
	meta:
		description = "Trojan:Win32/Staser.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 33 c0 33 db 90 59 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Staser.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 8b 44 24 10 8b f1 85 c0 6a 14 6a 40 ff 15 ?? ?? 46 00 8b f0 6a 01 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}