
rule Trojan_Win64_QuasarRAT_DA_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {2a 2a 50 49 5a 5a 41 20 54 4f 57 45 52 20 2a 2a 20 4e 65 77 20 43 6c 69 65 6e 74 2c } //20 **PIZZA TOWER ** New Client,
		$a_03_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-64] 2f [0-0f] 2e 62 61 74 [0-64] 26 43 4f 4d 50 55 54 45 52 4e 41 4d 45 } //1
		$a_01_2 = {2f 2f 64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //1 //discord.com/api/webhooks/
		$a_01_3 = {67 65 74 73 6f 63 6b 6e 61 6d 65 } //1 getsockname
		$a_01_4 = {67 65 74 70 65 65 72 6e 61 6d 65 } //1 getpeername
		$a_01_5 = {67 65 74 73 6f 63 6b 6f 70 74 } //1 getsockopt
		$a_01_6 = {73 65 74 73 6f 63 6b 6f 70 74 } //1 setsockopt
		$a_01_7 = {63 6c 6f 73 65 73 6f 63 6b 65 74 } //1 closesocket
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=27
 
}