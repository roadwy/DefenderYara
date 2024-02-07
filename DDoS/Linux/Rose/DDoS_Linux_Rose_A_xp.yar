
rule DDoS_Linux_Rose_A_xp{
	meta:
		description = "DDoS:Linux/Rose.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 6f 73 65 20 61 74 74 61 63 6b } //01 00  Rose attack
		$a_01_1 = {4e 65 77 44 61 77 6e 32 2e 63 } //01 00  NewDawn2.c
		$a_01_2 = {49 43 4d 50 20 66 72 61 67 6d 65 6e 74 73 } //01 00  ICMP fragments
		$a_01_3 = {3c 76 69 63 74 69 6d 3e 20 5b 73 6f 75 72 63 65 5d } //00 00  <victim> [source]
	condition:
		any of ($a_*)
 
}