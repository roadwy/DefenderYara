
rule Trojan_Win64_EspioLoader_A_MTB{
	meta:
		description = "Trojan:Win64/EspioLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c5 f7 74 24 90 01 01 48 8b 45 90 01 01 0f be 14 02 41 33 d0 48 8b 4f 90 01 01 4c 8b 47 90 01 01 49 3b c8 73 90 01 01 48 8d 41 90 01 01 48 89 47 90 01 01 48 8b c7 49 83 f8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}