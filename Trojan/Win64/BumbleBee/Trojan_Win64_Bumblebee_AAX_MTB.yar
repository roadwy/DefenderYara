
rule Trojan_Win64_Bumblebee_AAX_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 33 d2 48 c1 e8 0c 49 f7 34 c8 49 89 04 c8 48 b8 97 57 e9 56 a3 89 25 ad 4d 31 34 d9 0f b6 0d 7a ab 16 00 4c 8b 05 90 01 04 49 0b d8 48 f7 e3 48 c1 ea 09 41 32 d7 41 ff c7 0f b6 c2 0f af c8 88 0d 57 ab 16 00 45 3b fc 0f 8f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}