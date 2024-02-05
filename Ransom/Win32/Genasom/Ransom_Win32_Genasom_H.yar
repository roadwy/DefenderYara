
rule Ransom_Win32_Genasom_H{
	meta:
		description = "Ransom:Win32/Genasom.H,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 64 75 6c 74 66 61 6b 65 2e 72 75 2f 6d 65 6d 62 65 72 73 2e 70 68 70 00 6f 70 65 6e 00 } //01 00 
		$a_01_1 = {75 6e 69 78 74 69 6d 65 2e 64 61 74 00 00 00 00 5c 00 00 00 6c 6e 6b 2e 6c 6e 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}