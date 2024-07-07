
rule Trojan_Win32_Ursnif_NC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 c8 89 4c 24 18 8b 4c 24 10 83 d5 00 0f b6 c1 0f b6 ca 0f af c8 89 6c 24 20 89 4c 24 10 8b c1 8b 4c 24 18 2a c1 89 44 24 10 } //10
		$a_81_1 = {6c 69 74 74 6c 65 2d 73 68 6f 72 65 5c 33 35 38 5c 4c 65 76 65 6c 2e 70 64 62 } //3 little-shore\358\Level.pdb
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}