
rule Ransom_MacOS_EvilQuest_YA_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.YA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 62 74 70 79 72 63 2f 74 70 79 72 63 2e 63 } //01 00  libtpyrc/tpyrc.c
		$a_01_1 = {55 48 89 e5 48 83 ec 30 48 89 7d f0 48 c7 45 e8 00 00 00 00 48 8b 7d f0 48 8b 45 f0 48 89 7d d8 48 89 c7 e8 f4 23 00 00 48 8b 15 31 34 00 00 48 8b 7d d8 48 89 c6 48 8d 4d e8 e8 61 20 00 00 48 89 45 e0 48 83 7d e0 00 0f 85 0d 00 00 00 48 8b 45 f0 48 89 45 f8 e9 08 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}