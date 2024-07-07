
rule Trojan_Win32_Tibs_FU{
	meta:
		description = "Trojan:Win32/Tibs.FU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 12 5e c1 e0 18 b9 90 01 04 81 90 09 0b 00 ba 90 01 04 81 c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}