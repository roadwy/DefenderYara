
rule Trojan_Win32_Azorult_RSV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 90 01 05 b8 41 e5 64 03 81 6c 24 90 01 05 81 44 24 90 01 05 8b 4c 24 90 01 01 8b 90 01 01 d3 e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}