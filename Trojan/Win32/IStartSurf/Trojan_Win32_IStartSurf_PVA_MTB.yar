
rule Trojan_Win32_IStartSurf_PVA_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 08 8b 45 ?? 33 d2 f7 75 ?? 0f be 84 15 ?? ff ff ff 33 c8 8b 45 ?? 03 45 ?? 88 08 eb } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}