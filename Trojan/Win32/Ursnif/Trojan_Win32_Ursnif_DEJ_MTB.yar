
rule Trojan_Win32_Ursnif_DEJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 d3 e0 8b ce c1 e9 05 03 8d ?? fd ff ff 03 85 ?? fd ff ff 03 fe 33 c1 33 c7 89 85 ?? fd ff ff 8b 85 ?? fd ff ff 29 45 70 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}