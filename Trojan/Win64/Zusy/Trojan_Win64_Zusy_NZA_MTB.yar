
rule Trojan_Win64_Zusy_NZA_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 10 57 00 00 33 d2 48 8d 8c 24 ?? ?? ?? ?? e8 69 1c 00 00 48 8b 8c 24 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 89 41 40 48 8d 8c 24 50 01 } //3
		$a_03_1 = {eb 10 33 db 89 9c 24 ?? ?? ?? ?? 48 8d 35 a2 37 fd ff bf ?? ?? ?? ?? 8b cf e8 16 36 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}