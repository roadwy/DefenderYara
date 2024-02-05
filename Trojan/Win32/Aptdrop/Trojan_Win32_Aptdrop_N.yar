
rule Trojan_Win32_Aptdrop_N{
	meta:
		description = "Trojan:Win32/Aptdrop.N,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4e 3a 5c 43 23 4d 4d 5c 59 4b 4d 4d 5c 4c 6f 61 64 57 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 57 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}