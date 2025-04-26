
rule Trojan_Win32_AveMaria_B_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 bd 6c ff ff ff 89 95 60 ff ff ff 81 7d 90 00 00 00 01 74 1e 8b 45 80 03 45 90 0f be 00 8b 8d 60 ff ff ff 0f be 4c 0d 98 33 c1 8b 4d 80 03 4d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}