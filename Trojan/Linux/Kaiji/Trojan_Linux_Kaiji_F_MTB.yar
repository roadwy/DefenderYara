
rule Trojan_Linux_Kaiji_F_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 44 6e 73 5f 55 72 6c } //1 main.Dns_Url
		$a_01_1 = {6d 61 69 6e 2e 4b 69 6c 6c 73 68 } //1 main.Killsh
		$a_01_2 = {2f 63 6c 69 65 6e 74 2f 6c 69 6e 75 78 2f 6b 69 6c 6c 63 70 75 2e 67 6f } //1 /client/linux/killcpu.go
		$a_01_3 = {6d 61 69 6e 2e 67 65 74 77 65 62 77 61 6c 6b } //1 main.getwebwalk
		$a_01_4 = {6d 61 69 6e 2e 61 74 74 61 63 6b } //1 main.attack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}