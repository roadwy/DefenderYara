
rule Trojan_Linux_Kaiji_G_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 4b 69 6c 6c 63 70 75 } //1 main.Killcpu
		$a_01_1 = {6d 61 69 6e 2e 74 65 72 6d 69 6e 61 6c 72 75 6e } //1 main.terminalrun
		$a_01_2 = {6d 61 69 6e 2e 50 72 6f 78 79 68 61 6e 64 6c 65 } //1 main.Proxyhandle
		$a_01_3 = {6d 61 69 6e 2e 28 2a 41 6c 6c 6f 77 6c 69 73 74 29 2e 41 64 64 } //1 main.(*Allowlist).Add
		$a_01_4 = {6d 61 69 6e 2e 41 72 65 73 5f 54 63 70 5f 53 65 6e 64 } //1 main.Ares_Tcp_Send
		$a_01_5 = {2f 63 6c 69 65 6e 74 2f 6c 69 6e 75 78 2f 61 74 74 61 63 6b 2e 67 6f } //1 /client/linux/attack.go
		$a_01_6 = {6d 61 69 6e 2e 44 6e 73 5f 55 72 6c } //1 main.Dns_Url
		$a_01_7 = {6d 61 69 6e 2e 41 72 65 73 5f 69 70 73 70 6f 6f 66 } //1 main.Ares_ipspoof
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}