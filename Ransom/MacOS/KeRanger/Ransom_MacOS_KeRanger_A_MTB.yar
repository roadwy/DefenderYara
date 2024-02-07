
rule Ransom_MacOS_KeRanger_A_MTB{
	meta:
		description = "Ransom:MacOS/KeRanger.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 2f 4c 69 62 72 61 72 79 2f 2e 6b 65 72 6e 65 6c 5f 63 6f 6d 70 6c 65 74 65 } //01 00  %s/Library/.kernel_complete
		$a_00_1 = {52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 } //01 00  README_FOR_DECRYPT.txt
		$a_00_2 = {2e 6f 6e 69 6f 6e 2e 6e 75 } //01 00  .onion.nu
		$a_00_3 = {2e 6f 6e 69 6f 6e 2e 6c 69 6e 6b } //01 00  .onion.link
		$a_00_4 = {2e 65 6e 63 72 79 70 74 65 64 } //00 00  .encrypted
	condition:
		any of ($a_*)
 
}