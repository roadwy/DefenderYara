
rule Trojan_Win32_AveMaria_NEBU_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 2a 8b 8d 7c ff ff ff 03 8d 50 ff ff ff 0f be 11 8b 85 4c ff ff ff 0f be 4c 05 84 33 d1 8b 85 7c ff ff ff 03 85 50 ff ff ff 88 10 e9 57 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}