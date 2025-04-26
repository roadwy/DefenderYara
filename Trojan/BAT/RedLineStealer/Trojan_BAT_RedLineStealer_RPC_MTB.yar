
rule Trojan_BAT_RedLineStealer_RPC_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 00 } //1 cmd /c timeout 20
		$a_01_2 = {5a 00 73 00 7a 00 7a 00 44 00 6f 00 77 00 5a 00 73 00 7a 00 7a 00 6e 00 6c 00 5a 00 73 00 7a 00 7a 00 6f 00 61 00 64 00 44 00 5a 00 73 00 7a 00 7a 00 61 00 74 00 61 00 5a 00 73 00 7a 00 7a 00 } //1 ZszzDowZszznlZszzoadDZszzataZszz
		$a_01_3 = {38 00 31 00 2e 00 34 00 2e 00 31 00 30 00 35 00 2e 00 31 00 37 00 34 00 } //1 81.4.105.174
		$a_01_4 = {53 00 69 00 66 00 69 00 63 00 61 00 6e 00 2e 00 6c 00 6f 00 67 00 } //1 Sifican.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}