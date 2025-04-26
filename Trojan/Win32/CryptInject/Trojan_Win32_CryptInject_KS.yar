
rule Trojan_Win32_CryptInject_KS{
	meta:
		description = "Trojan:Win32/CryptInject.KS,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 61 6e 64 6c 65 72 2d 65 78 65 63 75 74 69 6f 6e 2e 65 78 65 } //1 handler-execution.exe
		$a_01_1 = {48 61 6e 64 6c 65 72 45 78 65 63 75 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //1 HandlerExecution.Properties
		$a_01_2 = {68 61 6e 64 6c 65 72 2d 65 78 65 63 75 74 69 6f 6e 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 handler-execution.g.resources
		$a_01_3 = {67 4a 6d 75 43 56 62 46 48 4c 69 4b 6a 47 61 47 4c 31 2e 74 48 37 6d 56 4c 77 61 34 52 65 70 67 57 67 63 58 65 } //1 gJmuCVbFHLiKjGaGL1.tH7mVLwa4RepgWgcXe
		$a_01_4 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_5 = {48 61 6e 64 6c 65 72 45 78 65 63 75 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 HandlerExecution.Properties.Resources.resources
		$a_01_6 = {68 61 6e 64 6c 65 72 2d 65 78 65 63 75 74 69 6f 6e 2e 70 64 62 } //1 handler-execution.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}