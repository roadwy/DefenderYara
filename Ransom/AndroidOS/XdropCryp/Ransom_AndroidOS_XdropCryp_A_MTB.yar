
rule Ransom_AndroidOS_XdropCryp_A_MTB{
	meta:
		description = "Ransom:AndroidOS/XdropCryp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6b 69 63 6f 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2f } //02 00  Lcom/example/kico/myapplication/
		$a_00_1 = {2f 61 64 64 73 6c 61 76 65 2e 70 68 70 } //01 00  /addslave.php
		$a_00_2 = {2f 72 61 6e 73 6f 2e 70 68 70 } //01 00  /ranso.php
		$a_00_3 = {2f 53 74 61 72 74 41 63 74 69 76 69 74 79 4f 6e 42 6f 6f 74 52 65 63 65 69 76 65 72 3b } //01 00  /StartActivityOnBootReceiver;
		$a_00_4 = {2e 78 64 72 6f 70 } //01 00  .xdrop
		$a_00_5 = {79 6f 75 72 20 61 6c 6c 20 70 68 6f 74 6f 73 20 61 6e 64 20 66 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 } //00 00  your all photos and files are Encrypted
	condition:
		any of ($a_*)
 
}