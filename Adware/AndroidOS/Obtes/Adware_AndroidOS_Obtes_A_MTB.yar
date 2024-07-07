
rule Adware_AndroidOS_Obtes_A_MTB{
	meta:
		description = "Adware:AndroidOS/Obtes.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 62 78 00 12 00 6e 30 90 01 02 47 00 12 00 6e 30 90 01 02 49 00 0c 00 1f 00 1a 00 6e 10 90 01 02 00 00 0b 0a 13 00 2f 00 33 02 2b 00 84 a0 23 00 2c 00 12 1a 23 aa 2e 00 12 0b 4d 00 0a 0b 6e 30 90 01 02 48 0a 21 0a d8 0a 0a fe 48 0a 00 0a 21 0b d8 0b 0b fe 12 1c 48 0c 00 0c 4f 0c 00 0b 12 1b 4f 0a 00 0b 54 ea 90 01 02 12 0b 71 20 90 01 02 b0 00 0c 00 4d 00 0a 02 d8 00 02 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}