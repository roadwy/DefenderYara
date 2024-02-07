
rule Trojan_Win64_Rozena_IG_MTB{
	meta:
		description = "Trojan:Win64/Rozena.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 83 f2 01 88 10 83 45 fc 01 8b 45 fc 3b 45 f8 7c d2 48 8b 45 10 48 83 c4 30 5d c3 } //01 00 
		$a_01_1 = {73 6f 63 6b 65 74 } //01 00  socket
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}