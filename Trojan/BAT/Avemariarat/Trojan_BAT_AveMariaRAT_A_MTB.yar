
rule Trojan_BAT_AveMariaRAT_A_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 4c 00 4e 00 4c 00 4f 00 4c 00 53 00 52 00 54 00 52 00 57 00 56 00 59 00 58 00 5a 00 58 00 5b 00 5a 00 5c 00 58 00 5d 00 58 00 } //2 MLNLOLSRTRWVYXZX[Z\X]X
		$a_01_1 = {58 00 61 00 58 00 62 00 58 00 63 00 58 00 64 00 58 00 65 00 58 00 66 00 58 00 67 00 58 00 6b 00 6a 00 6c 00 6a 00 6d 00 6a 00 6e 00 6a 00 6f 00 6a 00 70 00 6a 00 71 00 6a 00 } //2 XaXbXcXdXeXfXgXkjljmjnjojpjqj
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //2 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_3 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //2 costura.costura.dll.compressed
		$a_01_4 = {63 6f 73 74 75 72 61 2e 6e 65 77 74 6f 6e 73 6f 66 74 2e 6a 73 6f 6e 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //2 costura.newtonsoft.json.dll.compressed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}