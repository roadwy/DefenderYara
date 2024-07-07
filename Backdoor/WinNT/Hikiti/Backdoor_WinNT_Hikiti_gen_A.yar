
rule Backdoor_WinNT_Hikiti_gen_A{
	meta:
		description = "Backdoor:WinNT/Hikiti.gen.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 77 00 37 00 66 00 77 00 00 00 } //1
		$a_01_1 = {45 54 61 67 3a 20 22 25 78 25 78 25 78 3a 25 30 33 78 22 } //1 ETag: "%x%x%x:%03x"
		$a_02_2 = {3a 5c 53 6f 75 72 63 65 43 6f 64 65 5c 48 69 6b 69 74 5f 6e 65 77 5c 62 69 6e 33 32 5c 77 37 66 77 90 02 04 2e 70 64 62 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}