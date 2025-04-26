
rule Trojan_Win32_Stealc_EX_MTB{
	meta:
		description = "Trojan:Win32/Stealc.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d ec 8b 4d f0 d3 e8 03 45 d8 8b c8 8b 45 ec 31 45 fc 31 4d fc 2b 5d fc 8b 45 d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}