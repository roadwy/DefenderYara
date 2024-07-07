
rule Trojan_BAT_AgentTesla_NFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 73 79 6e 63 5c 73 79 6e 63 5c 62 69 6e 5c 44 65 62 75 67 5c 43 6f 6e 66 75 73 65 64 5c 73 79 6e 63 5f 65 6e 63 2e 70 64 62 } //1 source\repos\sync\sync\bin\Debug\Confused\sync_enc.pdb
		$a_81_1 = {66 73 74 61 74 76 66 73 40 6f 70 65 6e 73 73 68 2e 63 6f 6d } //1 fstatvfs@openssh.com
		$a_81_2 = {50 72 69 76 61 74 65 20 6b 65 79 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 62 75 74 20 70 61 73 73 70 68 72 61 73 65 20 69 73 20 65 6d 70 74 79 } //1 Private key is encrypted but passphrase is empty
		$a_81_3 = {73 79 6e 63 2e 65 78 65 } //1 sync.exe
		$a_81_4 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //1 Confuser.Core 1.6.0+447341964f
		$a_81_5 = {57 bf b6 3f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}