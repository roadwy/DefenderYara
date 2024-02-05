
rule Trojan_AndroidOS_Asacub_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Asacub.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 68 00 68 f1 60 08 60 a9 20 80 00 21 68 0b 58 00 25 b4 60 20 00 11 00 2a 00 98 47 01 78 00 29 30 d0 ea 43 71 60 30 39 ff 24 21 40 6b 1c 0a 29 00 d3 2b 00 81 18 89 78 01 32 00 29 08 b4 20 bc f1 d1 d9 1d 07 23 99 43 6b 46 59 1a 8d 46 00 25 00 2a 1a db 31 61 01 30 70 61 00 20 05 00 71 68 02 e0 71 69 09 5c 18 00 0b 00 30 3b 23 40 09 2b 02 d8 33 69 59 55 01 35 43 1c 90 42 f1 d1 f4 68 31 69 03 e0 00 25 f1 1d 15 31 f4 68 00 20 48 55 a7 20 82 00 b0 68 03 68 9a 58 90 47 07 49 79 44 09 68 09 68 22 68 89 1a 03 d1 fc 1f 05 3c a5 46 f0 bd 01 f0 } //00 00 
	condition:
		any of ($a_*)
 
}