
rule VirTool_BAT_Lamestri{
	meta:
		description = "VirTool:BAT/Lamestri,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 75 73 65 72 73 5c 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 64 65 73 6b 74 6f 70 5c 63 72 79 70 74 65 78 5c } //00 00  c:\users\administrator\desktop\cryptex\
	condition:
		any of ($a_*)
 
}