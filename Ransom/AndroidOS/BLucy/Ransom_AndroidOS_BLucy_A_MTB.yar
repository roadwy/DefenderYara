
rule Ransom_AndroidOS_BLucy_A_MTB{
	meta:
		description = "Ransom:AndroidOS/BLucy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 61 70 73 6f 69 6e 61 73 6a 72 71 39 31 32 30 71 77 70 73 61 6a 61 30 68 31 32 70 31 34 6b 6a 71 65 6f 71 30 72 31 68 67 66 30 33 64 73 68 6e 66 73 61 70 68 6b 6a 39 35 37 39 31 32 30 73 64 6a 62 74 39 31 35 39 39 66 67 30 62 76 } //01 00  gapsoinasjrq9120qwpsaja0h12p14kjqeoq0r1hgf03dshnfsaphkj9579120sdjbt91599fg0bv
		$a_00_1 = {68 74 74 70 2f 70 72 69 76 61 74 65 2f 73 65 74 5f 64 61 74 61 2e 70 68 70 } //01 00  http/private/set_data.php
		$a_00_2 = {68 74 74 70 2f 70 72 69 76 61 74 65 2f 72 65 67 2e 70 68 70 } //01 00  http/private/reg.php
		$a_00_3 = {68 74 74 70 2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70 } //01 00  http/private/add_log.php
		$a_00_4 = {6b 65 79 54 6f 45 } //00 00  keyToE
	condition:
		any of ($a_*)
 
}