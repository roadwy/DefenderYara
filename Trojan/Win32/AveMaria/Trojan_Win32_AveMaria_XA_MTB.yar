
rule Trojan_Win32_AveMaria_XA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 bd 74 ff ff ff 89 95 68 ff ff ff 8b 4d 84 03 8d 6c ff ff ff 0f be 09 8b 95 68 ff ff ff 0f be 44 15 8c 33 c8 e8 90 01 04 8b 4d 84 03 8d 6c ff ff ff 88 01 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}