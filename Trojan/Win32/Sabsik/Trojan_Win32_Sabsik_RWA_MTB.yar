
rule Trojan_Win32_Sabsik_RWA_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d ?? 8b 55 ?? 03 55 ?? 0f b6 0a 83 c1 47 8b 45 ?? 99 f7 7d ?? 8b 45 ?? 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}