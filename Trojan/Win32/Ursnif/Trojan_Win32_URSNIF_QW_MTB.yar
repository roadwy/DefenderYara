
rule Trojan_Win32_URSNIF_QW_MTB{
	meta:
		description = "Trojan:Win32/URSNIF.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 10 00 } //03 00 
		$a_81_1 = {6b 69 6c 6c 73 75 67 67 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}