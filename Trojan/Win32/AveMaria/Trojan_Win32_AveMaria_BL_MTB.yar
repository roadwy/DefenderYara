
rule Trojan_Win32_AveMaria_BL_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 7c ff ff ff 03 95 50 ff ff ff 0f be 02 8b 8d 4c ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 50 ff ff ff 88 01 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}