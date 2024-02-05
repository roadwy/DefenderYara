
rule VirTool_WinNT_Musomar_A{
	meta:
		description = "VirTool:WinNT/Musomar.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 95 57 53 89 5d 30 e8 90 01 02 ff ff 03 d8 85 f6 74 85 eb 19 3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 0b 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}