
rule Trojan_Win32_Remcos_RVA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 72 61 66 66 69 6e 61 64 65 72 69 65 72 73 5c 73 6a 6c 65 6d 65 73 73 65 73 2e 69 6e 69 } //1 \raffinaderiers\sjlemesses.ini
		$a_81_1 = {63 68 69 6e 6b 6c 65 20 69 67 6e 65 6f 61 71 75 65 6f 75 73 } //1 chinkle igneoaqueous
		$a_81_2 = {73 61 65 74 74 65 6d 61 73 6b 69 6e 65 6e 20 65 72 6b 65 6e 64 74 6c 69 67 68 65 64 20 65 64 69 74 69 6f 6e } //1 saettemaskinen erkendtlighed edition
		$a_81_3 = {73 65 6c 76 66 6f 72 67 75 64 65 6c 73 65 73 2e 65 78 65 } //1 selvforgudelses.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}