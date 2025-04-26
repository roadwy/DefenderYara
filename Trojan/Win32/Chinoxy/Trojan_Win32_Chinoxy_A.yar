
rule Trojan_Win32_Chinoxy_A{
	meta:
		description = "Trojan:Win32/Chinoxy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {40 53 45 54 20 53 4c 45 45 50 3d 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e } //1 @SET SLEEP=ping 127.0.0.1 -n
		$a_00_1 = {40 64 65 6c 20 66 73 65 77 65 77 66 72 74 72 65 74 72 77 77 65 2e 65 77 65 } //1 @del fsewewfrtretrwwe.ewe
		$a_00_2 = {40 65 63 68 6f 20 6b 6a 79 75 79 75 74 75 79 74 6e 66 67 66 68 67 68 64 3e 3e 66 73 65 77 65 77 66 72 74 72 65 74 72 77 77 65 2e 65 77 65 } //1 @echo kjyuyutuytnfgfhghd>>fsewewfrtretrwwe.ewe
		$a_01_3 = {00 43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 00 } //1 䌀湯牴汯敓癲捩e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}