
rule Trojan_Win64_XWorm_AMTB{
	meta:
		description = "Trojan:Win64/XWorm!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 79 6b 61 20 62 6c 79 61 74 2e 20 46 75 63 6b 20 61 6c 6c 2e 20 49 20 68 61 74 65 20 61 6c 6c 20 6f 66 20 79 6f 75 20 62 61 73 74 61 72 64 2e 20 49 20 73 61 79 20 68 69 20 74 6f 20 65 76 65 72 79 6f 6e 65 20 61 6e 64 20 77 69 73 68 20 79 6f 75 20 74 6f 20 67 6f 20 74 6f 20 68 65 6c 6c 2e } //Syka blyat. Fuck all. I hate any of you bastard. I say hi to everyone and wish you to go to hell.  2
		$a_80_1 = {49 20 68 6f 70 65 20 79 6f 75 20 72 65 61 6c 69 7a 65 20 79 6f 75 72 20 73 74 75 70 69 64 69 74 79 20 61 6e 64 20 64 69 65 2e } //I hope you realize your stupidity and die.  2
		$a_80_2 = {44 6f 42 72 6f 36 36 36 2e 20 4b 41 50 41 20 42 45 34 48 41 59 41 20 2e 30 37 2d 30 38 2d 32 35 2e 20 4d 61 64 65 20 69 6e 20 52 75 73 73 69 61 2e 20 54 68 65 54 68 69 6e 67 } //DoBro666. KAPA BE4HAYA .07-08-25. Made in Russia. TheThing  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}