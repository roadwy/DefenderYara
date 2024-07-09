
rule Trojan_Win64_Emotetcrypt_JQ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 8b 44 24 38 0f b6 04 08 44 33 c0 8b 05 ?? ?? ?? ?? 8b 0c 24 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 03 c1 03 d0 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 } //1
		$a_01_1 = {36 79 30 4b 57 24 61 61 59 7a 42 56 4d 47 37 59 72 58 55 50 6d 34 4d 26 5a 52 26 34 61 57 38 21 43 3c 67 37 2a 63 21 3f 69 35 64 29 41 26 40 44 25 26 38 5e 6c 34 4c 65 4a } //1 6y0KW$aaYzBVMG7YrXUPm4M&ZR&4aW8!C<g7*c!?i5d)A&@D%&8^l4LeJ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}