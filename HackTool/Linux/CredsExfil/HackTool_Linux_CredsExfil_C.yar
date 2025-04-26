
rule HackTool_Linux_CredsExfil_C{
	meta:
		description = "HackTool:Linux/CredsExfil.C,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 46 00 } //1 curl -F
		$a_00_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 2d 00 66 00 6f 00 72 00 6d 00 } //1 curl --form
		$a_00_2 = {2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00 } //10 /etc/shadow
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10) >=11
 
}