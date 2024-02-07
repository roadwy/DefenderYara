
rule Ransom_Linux_BlackBasta_B_MTB{
	meta:
		description = "Ransom:Linux/BlackBasta.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 72 75 63 74 69 6f 6e 73 5f 72 65 61 64 5f 6d 65 2e 74 78 74 } //02 00  instructions_read_me.txt
		$a_01_1 = {2d 64 69 73 61 62 6c 65 77 68 69 74 65 6c 69 73 74 } //02 00  -disablewhitelist
		$a_01_2 = {6f 66 69 6a 77 65 69 75 68 75 65 77 68 63 73 61 78 73 2e 6d 75 74 65 78 } //01 00  ofijweiuhuewhcsaxs.mutex
		$a_01_3 = {2d 6b 69 6c 6c 65 73 78 69 } //01 00  -killesxi
		$a_01_4 = {65 78 70 6f 72 74 20 70 72 6f 63 65 73 73 49 64 73 3d 24 28 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 } //00 00  export processIds=$(esxcli vm process list
	condition:
		any of ($a_*)
 
}