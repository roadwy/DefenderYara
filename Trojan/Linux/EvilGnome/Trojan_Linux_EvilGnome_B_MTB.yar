
rule Trojan_Linux_EvilGnome_B_MTB{
	meta:
		description = "Trojan:Linux/EvilGnome.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 64 67 36 32 5f 41 53 2e 73 61 24 64 69 65 33 } //1 sdg62_AS.sa$die3
		$a_00_1 = {72 74 70 2e 64 61 74 } //1 rtp.dat
		$a_00_2 = {67 6e 6f 6d 65 2d 73 68 65 6c 6c 2d 65 78 74 } //1 gnome-shell-ext
		$a_00_3 = {53 68 6f 6f 74 65 72 4b 65 79 } //1 ShooterKey
		$a_02_4 = {53 68 6f 6f 74 65 72 49 6d 61 67 65 90 02 02 74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}