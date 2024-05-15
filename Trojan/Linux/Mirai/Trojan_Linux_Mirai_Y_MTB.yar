
rule Trojan_Linux_Mirai_Y_MTB{
	meta:
		description = "Trojan:Linux/Mirai.Y!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {3c 1c 00 05 27 9c 90 01 02 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 90 01 02 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20 90 00 } //05 00 
		$a_00_1 = {10 00 00 07 00 a2 20 21 15 00 00 05 24 84 00 01 8c c2 00 00 00 00 00 00 24 42 00 01 ac c2 00 00 90 82 00 00 } //01 00 
		$a_00_2 = {33 6f 31 71 64 72 6d 66 70 32 6a 75 61 69 62 63 68 36 76 38 77 67 35 37 65 73 6c 30 6e 74 34 6b } //01 00  3o1qdrmfp2juaibch6v8wg57esl0nt4k
		$a_00_3 = {2e 6d 64 65 62 75 67 2e 61 62 69 33 32 } //00 00  .mdebug.abi32
	condition:
		any of ($a_*)
 
}