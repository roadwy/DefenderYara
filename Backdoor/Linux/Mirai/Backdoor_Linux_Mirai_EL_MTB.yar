
rule Backdoor_Linux_Mirai_EL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61 2e 72 65 6c 2e 72 6f 00 2e 64 61 74 61 00 2e 67 6f 74 00 2e 73 62 73 73 00 2e 62 73 73 00 2e 6d 64 65 62 75 67 2e 61 62 69 33 32 } //0a 00 
		$a_01_1 = {18 8f bf 08 a4 8f be 08 a0 8f b7 08 9c 8f b6 08 98 8f b5 08 94 8f b4 08 90 8f b3 08 8c 8f b2 08 88 8f b1 08 84 8f b0 08 80 03 e0 00 08 27 bd 08 a8 34 42 08 08 10 00 fe e0 af a2 08 70 3c 02 40 06 34 42 40 06 10 00 fe dc af a2 08 70 34 42 2a 2a 10 00 fe d9 af a2 08 70 1a 60 ff 78 02 37 b0 21 10 00 ff 79 af a0 00 20 2c a2 00 } //01 00 
		$a_01_2 = {2f 74 6d 70 2f 63 6f 6e 64 69 6e 65 74 77 6f 72 6b } //01 00  /tmp/condinetwork
		$a_01_3 = {39 39 3f 2a 2e 60 7a 2e 3f 22 2e 75 32 2e 37 36 76 3b 2a 2a 36 33 39 3b 2e 33 35 34 75 22 32 2e 37 36 71 22 37 36 76 3b 2a 2a 36 33 39 3b 2e 33 35 34 75 22 37 36 61 2b 67 6a 74 63 76 33 37 3b 3d 3f 75 2d 3f 38 2a 76 70 75 70 61 2b 67 6a 74 62 5a } //00 00  99?*.`z.?".u2.76v;**639;.354u"2.76q"76v;**639;.354u"76a+gjtcv37;=?u-?8*vpupa+gjtbZ
	condition:
		any of ($a_*)
 
}