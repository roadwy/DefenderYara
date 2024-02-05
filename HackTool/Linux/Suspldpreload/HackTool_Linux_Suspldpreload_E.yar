
rule HackTool_Linux_Suspldpreload_E{
	meta:
		description = "HackTool:Linux/Suspldpreload.E,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 00 44 00 5f 00 50 00 52 00 45 00 4c 00 4f 00 41 00 44 00 3d 00 2f 00 74 00 6d 00 70 00 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}