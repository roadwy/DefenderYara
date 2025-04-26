
rule Backdoor_Win32_Turkojan_gen_A{
	meta:
		description = "Backdoor:Win32/Turkojan.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 75 72 6b 6f 6a 61 6e 20 53 65 72 76 65 72 } //1 Turkojan Server
		$a_02_1 = {54 75 72 6b 6f 6a 61 6e 20 ?? 2e 30 } //1
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 75 72 6b 6f 6a 61 6e 2e 63 6f 6d } //1 http://www.turkojan.com
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}