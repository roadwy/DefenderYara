
rule Trojan_Win32_Sabsik_RWA_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 7d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 0a 83 c1 47 8b 45 90 01 01 99 f7 7d 90 01 01 8b 45 90 01 01 0f be 14 10 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}