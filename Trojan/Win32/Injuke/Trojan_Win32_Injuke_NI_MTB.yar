
rule Trojan_Win32_Injuke_NI_MTB{
	meta:
		description = "Trojan:Win32/Injuke.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 19 fc 29 f9 29 ce 01 d9 c1 e9 ?? f3 a5 eb bc 0f b7 84 1d ?? ?? ?? ?? 66 89 44 19 fe e9 36 fd ff ff 0f b7 84 1d ?? ?? ?? ?? 66 89 44 19 fe eb 9b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}