
rule DDoS_Linux_Chalubo_A_MTB{
	meta:
		description = "DDoS:Linux/Chalubo.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 68 63 70 72 65 6e 65 77 } //0a 00  dhcprenew
		$a_02_1 = {3a 38 38 35 32 2f 52 54 45 47 46 4e 30 31 3b 90 02 04 3a 2f 2f 90 02 15 2e 63 6f 6d 3a 38 38 35 32 2f 52 54 45 47 46 4e 30 31 90 00 } //01 00 
		$a_00_2 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 74 6d 70 2e 6c } //01 00  /data/local/tmp/tmp.l
		$a_00_3 = {2f 74 6d 70 2f 74 6d 70 6e 61 6d 5f 58 58 58 58 58 58 } //00 00  /tmp/tmpnam_XXXXXX
	condition:
		any of ($a_*)
 
}