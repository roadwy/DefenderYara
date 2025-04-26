
rule Trojan_Win32_Bublik_AYA_MTB{
	meta:
		description = "Trojan:Win32/Bublik.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 8d 1c 3e 29 f2 8b cb e8 e9 ff ff ff 89 f2 89 f9 e8 e0 ff ff ff 33 c0 09 f6 74 11 8a 14 03 8a 0c 38 88 14 38 88 0c 03 40 39 f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}