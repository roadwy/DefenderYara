
rule Ransom_AndroidOS_SauranLocker_A{
	meta:
		description = "Ransom:AndroidOS/SauranLocker.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00  .encrypted
		$a_00_1 = {7b 7b 57 41 4c 4c 45 54 7d 7d } //01 00  {{WALLET}}
		$a_00_2 = {2f 67 61 74 65 77 61 79 2f 61 74 74 61 63 68 2e 70 68 70 3f 75 69 64 3d } //01 00  /gateway/attach.php?uid=
		$a_02_3 = {4c 63 6f 6d 2f 90 02 40 2f 90 02 40 2f 4c 6f 63 6b 41 63 74 69 76 69 74 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}