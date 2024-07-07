
rule Trojan_Win32_AveMaria_NEBM_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 24 8b 8d 7c ff ff ff 03 4d 90 0f be 11 8b 85 60 ff ff ff 0f be 4c 05 98 33 d1 8b 85 7c ff ff ff 03 45 90 88 10 eb 85 } //5
		$a_01_1 = {8b 55 90 83 c2 01 89 55 90 8b 45 90 3b 85 64 ff ff ff 7d 67 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}