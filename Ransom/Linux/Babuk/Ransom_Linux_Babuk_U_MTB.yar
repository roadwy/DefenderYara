
rule Ransom_Linux_Babuk_U_MTB{
	meta:
		description = "Ransom:Linux/Babuk.U!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 6e 65 74 77 6f 72 6b 20 6e 69 63 20 6c 69 73 74 } //1 esxcli --formatter=csv network nic list
		$a_01_1 = {56 4d 58 43 61 72 74 65 6c 49 44 } //1 VMXCartelID
		$a_01_2 = {76 6d 43 6f 75 6e 74 20 25 64 20 61 66 66 65 63 74 65 64 56 6d 43 6f 75 6e 74 20 25 64 20 76 6d 54 6f 74 61 6c 43 6f 75 6e 74 } //1 vmCount %d affectedVmCount %d vmTotalCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}