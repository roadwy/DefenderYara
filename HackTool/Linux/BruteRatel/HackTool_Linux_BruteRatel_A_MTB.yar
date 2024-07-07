
rule HackTool_Linux_BruteRatel_A_MTB{
	meta:
		description = "HackTool:Linux/BruteRatel.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 4d 69 74 72 65 53 74 72 75 63 74 } //1 main.MitreStruct
		$a_00_1 = {75 72 6c 2e 55 73 65 72 69 6e 66 6f } //1 url.Userinfo
		$a_00_2 = {76 69 63 74 69 6d 73 69 7a 65 } //1 victimsize
		$a_00_3 = {46 6f 72 63 65 41 74 74 65 6d 70 74 48 54 54 50 } //1 ForceAttemptHTTP
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}