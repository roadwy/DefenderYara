
rule Trojan_PowerShell_PowDow_DG_MTB{
	meta:
		description = "Trojan:PowerShell/PowDow.DG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 72 00 61 00 6e 00 64 00 69 00 6e 00 67 00 73 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 73 00 74 00 6f 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 74 00 61 00 74 00 69 00 63 00 5f 00 69 00 6d 00 61 00 67 00 65 00 2f 00 } //10 brandingsolutionstore.com/static_image/
		$a_00_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 2d 00 69 00 6e 00 73 00 65 00 63 00 75 00 72 00 65 00 } //1 curl --insecure
		$a_00_2 = {2d 00 58 00 20 00 50 00 4f 00 53 00 54 00 20 00 2d 00 64 00 } //1 -X POST -d
		$a_00_3 = {2d 00 73 00 53 00 4c 00 20 00 2d 00 48 00 } //1 -sSL -H
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=13
 
}