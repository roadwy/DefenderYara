
rule Trojan_Win32_Copak_SPDS_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 14 8a 43 00 46 01 c9 e8 ?? ?? ?? ?? 29 f1 01 f1 31 10 09 f6 40 89 f1 46 81 ee 4f 51 ca 52 39 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}