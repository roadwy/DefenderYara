
rule HackTool_Linux_Linikatz_F{
	meta:
		description = "HackTool:Linux/Linikatz.F,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 64 00 20 00 2d 00 65 00 20 00 73 00 2f 00 2e 00 2a 00 63 00 61 00 63 00 68 00 65 00 64 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 2a 00 5c 00 24 00 36 00 5c 00 24 00 2f 00 5c 00 24 00 36 00 5c 00 24 00 2f 00 67 00 20 00 2d 00 65 00 20 00 73 00 2f 00 5c 00 5c 00 30 00 30 00 6c 00 61 00 73 00 74 00 43 00 61 00 63 00 68 00 65 00 64 00 2e 00 2a 00 2f 00 2f 00 67 00 } //1 sed -e s/.*cachedPassword.*\$6\$/\$6\$/g -e s/\\00lastCached.*//g
	condition:
		((#a_00_0  & 1)*1) >=1
 
}