
rule DDoS_Linux_Flooder_M_xp{
	meta:
		description = "DDoS:Linux/Flooder.M!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 6c 6f 6f 64 70 6f 72 74 } //2 floodport
		$a_01_1 = {43 55 53 54 4f 4d 2d 55 44 50 } //1 CUSTOM-UDP
		$a_01_2 = {55 73 61 67 65 3a 20 25 73 20 3c 49 50 3e 20 3c 50 4f 52 54 3e 20 3c 50 41 59 4c 4f 41 44 3e } //1 Usage: %s <IP> <PORT> <PAYLOAD>
		$a_01_3 = {41 74 74 61 63 6b 20 73 68 6f 75 6c 64 20 62 65 20 73 74 61 72 74 65 64 20 6e 6f 77 2e } //1 Attack should be started now.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}