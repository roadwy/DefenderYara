
rule Trojan_AndroidOS_Iop_C_xp{
	meta:
		description = "Trojan:AndroidOS/Iop.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 44 88 03 00 47 88 21 48 80 00 b0 23 67 98 04 00 49 98 08 00 48 90 09 00 4a 90 20 80 99 8f 28 01 b0 af 18 00 b0 27 2c 01 bf af 1c 01 a7 af 20 01 a9 af 24 01 a8 a3 25 01 aa a3 10 00 bc af 1c 01 a4 } //01 00 
		$a_00_1 = {34 00 a2 27 38 02 79 8c 18 00 a2 af 09 f8 20 03 21 38 40 00 24 00 bf 8f 08 00 e0 03 28 00 bd 27 09 00 1c 3c 04 89 9c 27 21 e0 99 03 1c 80 83 8f b8 ff bd 27 bc 23 62 24 03 00 49 88 07 00 48 88 0b 00 47 88 0f 00 46 88 13 00 45 88 17 00 44 88 1b 00 4a 88 10 00 bc af 44 00 bf } //00 00 
	condition:
		any of ($a_*)
 
}