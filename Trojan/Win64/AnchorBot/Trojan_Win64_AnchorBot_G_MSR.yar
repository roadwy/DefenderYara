
rule Trojan_Win64_AnchorBot_G_MSR{
	meta:
		description = "Trojan:Win64/AnchorBot.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 69 6d 73 69 6d 5c 61 6e 63 68 6f 72 44 4e 53 2e 76 35 5c 42 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 61 6e 63 68 6f 72 44 4e 53 5f 78 36 34 2e 70 64 62 } //01 00 
		$a_01_1 = {78 77 70 77 70 70 } //00 00 
		$a_00_2 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}