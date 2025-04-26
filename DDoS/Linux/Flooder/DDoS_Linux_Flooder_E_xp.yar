
rule DDoS_Linux_Flooder_E_xp{
	meta:
		description = "DDoS:Linux/Flooder.E!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 6e 41 74 74 61 63 6b 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 fnAttackInformation
		$a_00_1 = {64 71 79 65 66 6c 64 69 2f 72 65 73 70 6f 6e 73 65 2e 70 68 70 } //1 dqyefldi/response.php
		$a_00_2 = {43 68 61 6e 67 65 74 6f 44 6e 73 4e 61 6d 65 46 6f 72 6d 61 74 } //1 ChangetoDnsNameFormat
		$a_00_3 = {44 4e 53 20 46 6c 6f 6f 64 65 72 20 76 31 2e 31 } //1 DNS Flooder v1.1
		$a_00_4 = {55 73 61 67 65 3a 20 25 73 20 3c 74 61 72 67 65 74 20 49 50 2f 68 6f 73 74 6e 61 6d 65 3e } //1 Usage: %s <target IP/hostname>
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}