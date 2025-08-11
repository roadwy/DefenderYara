
rule Trojan_Linux_SAgnt_AD_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.AD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 8f f2 ff 14 e8 82 0b fe ff 49 8b 41 08 49 8b 11 49 81 e9 08 00 00 00 48 0f ab dd 66 d3 d5 48 f7 e2 48 0f b7 ee 49 0f bf ec 49 89 51 08 41 0f b7 ee 66 f7 d5 49 0f b7 eb 49 89 41 10 9c 40 86 ed 66 d1 cd 41 8f 01 40 d2 cd 49 0b eb 49 81 eb 04 00 00 00 41 02 ec f5 40 d2 ed 41 8b 2b 41 3b dc f5 f9 33 ee 81 c5 1c 68 f3 3c f9 f8 d1 cd 66 f7 c3 2b 7e 0f cd 80 fa 1d f7 dd f8 } //1
		$a_01_1 = {56 44 31 14 24 66 44 85 cb 66 41 0f b6 f1 f8 5e 4d 63 d2 f9 f5 e9 db 46 fd ff 81 f2 36 43 32 1c 41 51 41 f6 c7 4d 31 14 24 41 59 48 63 d2 45 3a e6 f9 4c 03 d2 e9 96 c6 00 00 f7 d1 e9 1c 7a 00 00 49 0f ba e0 39 31 0c 24 41 80 c0 51 49 c1 d8 89 44 1a c6 41 58 f6 c7 71 48 63 c9 45 3a e4 4c 03 d1 e9 60 fc 32 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}