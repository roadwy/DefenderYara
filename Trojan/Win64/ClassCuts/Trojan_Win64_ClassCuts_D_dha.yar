
rule Trojan_Win64_ClassCuts_D_dha{
	meta:
		description = "Trojan:Win64/ClassCuts.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 65 78 70 6c 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 } //1 delkill /F /IM explENT_USER\Softwar
		$a_01_1 = {5b 2b 5d 20 53 68 6f 72 74 54 69 6d 65 72 20 61 6e 64 20 46 61 69 6c 43 6f 75 6e 74 65 72 20 63 68 61 6e 67 65 64 2e } //1 [+] ShortTimer and FailCounter changed.
		$a_01_2 = {5b 2b 5d 20 45 6e 64 70 6f 69 6e 74 20 63 68 61 6e 67 65 64 } //1 [+] Endpoint changed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}