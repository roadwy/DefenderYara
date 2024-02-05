
rule Trojan_Win32_GandCrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e8 05 03 44 24 18 8b cf c1 e1 04 03 4c 24 1c 8d 14 3b 33 c1 33 c2 2b f0 8b c6 c1 e8 05 03 44 24 20 8b ce c1 e1 04 03 4c 24 24 8d 14 33 33 c1 33 c2 45 2b f8 } //00 00 
	condition:
		any of ($a_*)
 
}