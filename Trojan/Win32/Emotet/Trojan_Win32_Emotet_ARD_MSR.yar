
rule Trojan_Win32_Emotet_ARD_MSR{
	meta:
		description = "Trojan:Win32/Emotet.ARD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //1 CryptUnprotectData
		$a_01_1 = {44 72 6f 70 20 62 6f 6d 62 20 28 70 6f 6f 70 29 3a } //1 Drop bomb (poop):
		$a_01_2 = {6f 77 6e 65 72 20 64 65 61 64 } //1 owner dead
		$a_01_3 = {62 72 6f 6b 65 6e 20 70 69 70 65 } //1 broken pipe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}