
rule Trojan_Linux_RemovalOnHost_F{
	meta:
		description = "Trojan:Linux/RemovalOnHost.F,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 00 6d 00 20 00 2d 00 72 00 66 00 } //1 rm -rf
		$a_00_1 = {72 00 6d 00 20 00 2d 00 66 00 72 00 } //1 rm -fr
		$a_00_2 = {72 00 6d 00 20 00 2d 00 72 00 20 00 2d 00 66 00 } //1 rm -r -f
		$a_00_3 = {72 00 6d 00 20 00 2d 00 66 00 20 00 2d 00 72 00 } //1 rm -f -r
		$a_00_4 = {20 00 2f 00 20 00 } //5  / 
		$a_00_5 = {2d 00 2d 00 6e 00 6f 00 2d 00 70 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 2d 00 72 00 6f 00 6f 00 74 00 } //10 --no-preserve-root
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*5+(#a_00_5  & 1)*10) >=16
 
}