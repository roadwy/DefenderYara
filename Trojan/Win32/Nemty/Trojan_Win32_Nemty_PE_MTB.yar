
rule Trojan_Win32_Nemty_PE_MTB{
	meta:
		description = "Trojan:Win32/Nemty.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 1c 0a 8b c0 3b 4c 24 04 8b c0 7d 09 8b c0 83 c1 04 8b c0 eb ea } //01 00 
		$a_02_1 = {33 c0 8a 83 90 01 04 2b c3 40 8b c8 83 e0 01 d1 e9 83 e1 7f c1 e0 07 0b c8 8d 44 59 53 33 c3 8b d0 c1 ea 04 80 e2 0f c0 e0 04 0a d0 fe c2 32 d3 f6 d2 02 d3 80 f2 ae 2a d3 fe c2 32 d3 80 f2 d4 2a d3 80 ea 6b 88 93 90 01 04 43 81 fb 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}