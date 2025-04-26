
rule Trojan_Win32_Krypter_AH_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 32 02 aa 42 e2 ?? 61 5d c2 10 00 90 0a 20 00 60 8b 7d ?? 8b 75 ?? 8b 4d ?? 8b 55 ?? 80 3a ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}