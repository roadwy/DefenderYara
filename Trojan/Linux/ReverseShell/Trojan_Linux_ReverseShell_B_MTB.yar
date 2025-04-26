
rule Trojan_Linux_ReverseShell_B_MTB{
	meta:
		description = "Trojan:Linux/ReverseShell.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 41 73 56 69 72 75 73 } //1 main.AsVirus
		$a_01_1 = {6d 61 69 6e 2e 52 65 6d 6f 76 65 53 65 6c 66 45 78 65 63 75 74 61 62 6c 65 } //1 main.RemoveSelfExecutable
		$a_01_2 = {6d 61 69 6e 2e 53 74 61 72 74 53 6f 63 6b 73 35 53 65 72 76 65 72 } //1 main.StartSocks5Server
		$a_01_3 = {6d 61 69 6e 2e 43 72 65 61 74 65 42 61 63 6b 4f 66 66 } //1 main.CreateBackOff
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}