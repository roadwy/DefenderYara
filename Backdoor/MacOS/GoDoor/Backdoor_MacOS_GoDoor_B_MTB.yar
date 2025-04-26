
rule Backdoor_MacOS_GoDoor_B_MTB{
	meta:
		description = "Backdoor:MacOS/GoDoor.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 67 6f 53 68 65 6c 6c } //2 main.goShell
		$a_01_1 = {6e 65 74 2e 67 6f 4c 6f 6f 6b 75 70 50 6f 72 74 } //2 net.goLookupPort
		$a_01_2 = {6d 61 69 6e 2e 70 65 72 73 69 73 74 65 6e 63 65 } //2 main.persistence
		$a_01_3 = {52 65 76 65 72 73 65 47 6f 53 68 65 6c 6c 2d 6d 61 73 74 65 72 2f 73 72 63 2f 63 6c 69 65 6e 74 5f 4d 61 63 5f 72 65 31 2e 67 6f } //1 ReverseGoShell-master/src/client_Mac_re1.go
		$a_01_4 = {2f 72 6f 6f 74 2f 6d 61 6c 77 61 72 65 2f 6d 61 6c 77 61 72 65 4b 69 6c 6c 65 72 2e 67 6f } //1 /root/malware/malwareKiller.go
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}