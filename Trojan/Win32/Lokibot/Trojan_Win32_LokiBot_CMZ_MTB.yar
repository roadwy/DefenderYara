
rule Trojan_Win32_LokiBot_CMZ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea ?? 8d 0c 52 c1 e1 ?? 2b c1 8a 80 ?? ?? ?? ?? 30 04 33 46 3b f7 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}