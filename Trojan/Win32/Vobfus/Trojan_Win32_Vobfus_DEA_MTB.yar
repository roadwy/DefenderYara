
rule Trojan_Win32_Vobfus_DEA_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 d3 e0 03 fb c1 eb 05 03 9d ?? fd ff ff 03 85 ?? fd ff ff 89 bd ?? fd ff ff 89 45 f8 8b 85 ?? fd ff ff 31 45 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}