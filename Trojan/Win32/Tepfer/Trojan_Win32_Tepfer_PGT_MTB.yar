
rule Trojan_Win32_Tepfer_PGT_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c6 89 84 b5 74 ec ff ff 46 3b f2 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}