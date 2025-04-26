
rule Trojan_Win32_Qukart_GZA_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 83 ec ?? 56 57 bf ?? ?? ?? ?? 89 f8 f7 e7 89 45 ?? 89 c7 31 f8 89 c7 8d 45 ?? 50 8d 45 ?? 50 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 75 ?? ff 75 ?? e8 ?? ?? ?? ?? 89 c6 09 f6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}