
rule Trojan_Linux_Kaiji_B_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 73 68 61 74 74 61 63 6b 2e 66 75 6e 63 31 } //2 sshattack.func1
		$a_00_1 = {64 64 6f 73 2e 55 64 70 66 6c 6f 6f 64 61 } //2 ddos.Udpflooda
		$a_00_2 = {6f 73 2f 75 73 65 72 2e 6c 6f 6f 6b 75 70 55 73 65 72 49 64 } //1 os/user.lookupUserId
		$a_00_3 = {64 64 6f 73 2e 52 75 6e 73 68 65 6c 6c 6b 69 6c 6c } //1 ddos.Runshellkill
		$a_00_4 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 4e 65 77 43 46 42 44 65 63 72 79 70 74 65 72 } //1 crypto/cipher.NewCFBDecrypter
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}