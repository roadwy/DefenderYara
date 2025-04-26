
rule Trojan_Win32_Daonol_gen_A{
	meta:
		description = "Trojan:Win32/Daonol.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 18 46 00 00 ac 32 c2 80 c2 ?? (88 46 ff|aa) e2 } //1
		$a_03_1 = {bd 19 46 00 00 30 9e ?? ?? ?? ?? 46 [0-02] ff d7 80 eb ?? 4d 75 } //1
		$a_03_2 = {bd 19 46 00 00 81 c6 ?? ?? ?? ?? 53 46 8a 24 24 30 24 2e 46 (ff d7|e8 ?? ?? ??) ?? 80 eb ?? 4d 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}