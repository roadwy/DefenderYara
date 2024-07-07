
rule DDoS_Linux_Kaiten_A_MTB{
	meta:
		description = "DDoS:Linux/Kaiten.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 16 c7 44 24 04 09 00 00 00 c7 04 24 00 00 00 00 e8 90 01 02 00 00 eb 3c a1 90 01 02 06 08 c7 44 24 18 02 00 00 00 c7 44 24 14 03 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 02 00 00 00 89 44 24 08 c7 44 24 04 bc a1 05 08 8b 45 08 89 04 24 90 00 } //1
		$a_00_1 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 6c 6f 63 61 6c } //1 /etc/rc.d/rc.local
		$a_00_2 = {44 69 73 6d 61 79 27 73 20 49 52 43 20 42 6f 74 } //1 Dismay's IRC Bot
		$a_00_3 = {62 6f 74 20 2b 75 6e 6b 6e 6f 77 6e 20 3c 74 61 72 67 65 74 3e 20 3c 73 65 63 73 3e } //1 bot +unknown <target> <secs>
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}