
rule DDoS_Linux_Flooder_Dx_xp{
	meta:
		description = "DDoS:Linux/Flooder.Dx!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 6f 6f 66 65 64 20 55 44 50 20 46 6c 6f 6f 64 65 72 } //01 00  Spoofed UDP Flooder
		$a_00_1 = {53 74 61 72 74 69 6e 67 20 46 6c 6f 6f 64 } //01 00  Starting Flood
		$a_00_2 = {6d 79 53 74 72 43 61 74 } //01 00  myStrCat
		$a_00_3 = {73 75 64 70 2e 63 } //01 00  sudp.c
		$a_00_4 = {3c 74 61 72 67 65 74 20 49 50 2f 68 6f 73 74 6e 61 6d 65 3e 20 3c 70 6f 72 74 20 74 6f 20 62 65 20 66 6c 6f 6f 64 65 64 3e 20 } //01 00  <target IP/hostname> <port to be flooded> 
		$a_00_5 = {72 61 6e 64 5f 63 6d 77 63 } //00 00  rand_cmwc
	condition:
		any of ($a_*)
 
}