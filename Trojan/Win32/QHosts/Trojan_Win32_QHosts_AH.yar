
rule Trojan_Win32_QHosts_AH{
	meta:
		description = "Trojan:Win32/QHosts.AH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {4b 83 fb 00 76 06 40 80 30 ?? eb f4 5b } //4
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //2 \system32\drivers\etc\hosts
		$a_00_2 = {62 61 6e 63 6f 64 65 63 68 69 6c 65 2e 63 6c } //1 bancodechile.cl
		$a_00_3 = {62 61 6e 63 6f 65 73 74 61 64 6f 2e 63 6c } //1 bancoestado.cl
		$a_00_4 = {62 62 76 61 2e 63 6c } //1 bbva.cl
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}