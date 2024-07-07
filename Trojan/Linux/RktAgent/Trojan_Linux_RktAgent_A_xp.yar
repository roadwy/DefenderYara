
rule Trojan_Linux_RktAgent_A_xp{
	meta:
		description = "Trojan:Linux/RktAgent.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 64 65 76 2f 70 72 6f 63 2f 66 75 63 6b 69 74 2f 63 6f 6e 66 69 67 2f 72 70 6f 72 74 73 } //1 /dev/proc/fuckit/config/rports
		$a_00_1 = {28 48 29 69 64 64 65 6e 20 70 72 6f 67 72 61 6d 73 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 (H)idden programs configuration
		$a_00_2 = {28 42 29 61 63 6b 64 6f 6f 72 20 70 61 73 73 77 6f 72 64 } //1 (B)ackdoor password
		$a_00_3 = {46 75 63 4b 69 74 20 52 4b 20 62 79 20 43 79 72 61 78 } //1 FucKit RK by Cyrax
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}