
rule VirTool_WinNT_Nedsym_gen_B{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 f6 74 85 eb 19 3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 0b 6a 00 57 ff 75 30 e8 e2 fd ff ff 5f } //00 00 
	condition:
		any of ($a_*)
 
}