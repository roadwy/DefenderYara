
rule Trojan_WinNT_Alureon_P{
	meta:
		description = "Trojan:WinNT/Alureon.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 d8 08 c0 0f 85 90 01 02 00 80 6a 00 ff 15 90 01 02 01 00 68 90 01 02 00 00 6a 00 ff 15 90 01 02 01 00 a3 90 01 02 01 00 89 c7 be 90 01 02 01 00 bb 90 01 02 00 00 a5 31 5f fc 81 c3 90 01 02 00 00 81 fe 90 01 02 01 00 0f 85 ea ff ff ff ff 15 90 01 02 01 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}