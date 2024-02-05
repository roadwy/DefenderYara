
rule Trojan_Win32_Krypter_AH_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 32 02 aa 42 e2 90 01 01 61 5d c2 10 00 90 0a 20 00 60 8b 7d 90 01 01 8b 75 90 01 01 8b 4d 90 01 01 8b 55 90 01 01 80 3a 90 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}