
rule Trojan_Win64_GhostStealer_AMTB{
	meta:
		description = "Trojan:Win64/GhostStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 67 68 6f 73 74 5f } //C:\Windows\Temp\ghost_  1
		$a_80_1 = {47 68 6f 73 74 53 74 65 61 6c 65 72 2e 70 64 62 } //GhostStealer.pdb  1
		$a_80_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 64 61 74 61 5f } //C:\Windows\Temp\data_  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}