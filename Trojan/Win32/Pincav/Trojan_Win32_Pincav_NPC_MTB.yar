
rule Trojan_Win32_Pincav_NPC_MTB{
	meta:
		description = "Trojan:Win32/Pincav.NPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 94 24 ca 01 00 00 83 c4 0c 8d 8c 24 ?? ?? ?? ?? 8a 84 24 bc 01 00 00 30 42 ?? 42 39 ca 75 f1 } //5
		$a_01_1 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}