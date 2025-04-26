
rule Trojan_Win32_Cipduk_F_dha{
	meta:
		description = "Trojan:Win32/Cipduk.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 3a 5c 50 42 5c 56 53 41 67 65 6e 74 5c [0-02] 5c 73 5c 43 6c 69 65 6e 74 5c 53 6f 75 72 63 65 5c 43 6c 69 65 6e 74 53 6f 75 72 63 65 5c 52 65 6c 65 61 73 65 5c 50 42 43 6f 6e 66 69 67 2e 70 64 62 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}