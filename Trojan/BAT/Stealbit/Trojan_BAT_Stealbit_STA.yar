
rule Trojan_BAT_Stealbit_STA{
	meta:
		description = "Trojan:BAT/Stealbit.STA,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 68 6f 73 74 2e 2e 2e } //1 Connecting to host...
		$a_01_1 = {7c 20 53 74 6f 70 2d 50 72 6f 63 65 73 73 20 2d 46 6f 72 63 65 } //1 | Stop-Process -Force
		$a_01_2 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 70 61 74 68 } //1 Remove-Item -Path $path
		$a_01_3 = {53 53 48 2d 32 2e 30 2d 52 65 6e 63 69 2e 53 73 68 4e 65 74 2e 53 73 68 43 6c 69 65 6e 74 2e } //1 SSH-2.0-Renci.SshNet.SshClient.
		$a_01_4 = {73 63 70 20 2d 72 20 2d 70 20 2d 64 20 2d 74 20 7b 30 7d } //1 scp -r -p -d -t {0}
		$a_01_5 = {31 36 35 2e 32 32 2e 38 34 2e 31 34 37 } //2 165.22.84.147
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=5
 
}