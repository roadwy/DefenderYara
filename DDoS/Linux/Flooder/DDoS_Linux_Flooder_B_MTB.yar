
rule DDoS_Linux_Flooder_B_MTB{
	meta:
		description = "DDoS:Linux/Flooder.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 61 6e 64 5f 63 6d 77 63 } //01 00  rand_cmwc
		$a_01_1 = {73 65 74 75 70 5f 75 64 70 5f 68 65 61 64 65 72 } //01 00  setup_udp_header
		$a_01_2 = {73 65 74 75 70 5f 69 70 5f 68 65 61 64 65 72 } //01 00  setup_ip_header
		$a_01_3 = {63 73 75 6d } //00 00  csum
	condition:
		any of ($a_*)
 
}