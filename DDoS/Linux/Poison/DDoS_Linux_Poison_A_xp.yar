
rule DDoS_Linux_Poison_A_xp{
	meta:
		description = "DDoS:Linux/Poison.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 46 50 6f 69 73 6f 6e 2e 63 } //1 RFPoison.c
		$a_01_1 = {50 6f 69 73 6f 6e 20 70 61 63 6b 65 74 } //1 Poison packet
		$a_01_2 = {72 66 70 6f 69 73 6f 6e 20 3c 69 70 20 6f 66 20 74 61 72 67 65 74 3e } //1 rfpoison <ip of target>
		$a_01_3 = {5c 2a 53 4d 42 53 45 52 56 45 52 } //1 \*SMBSERVER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}