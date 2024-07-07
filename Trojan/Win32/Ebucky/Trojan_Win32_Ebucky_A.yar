
rule Trojan_Win32_Ebucky_A{
	meta:
		description = "Trojan:Win32/Ebucky.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b1 7e 30 0d 90 01 04 30 0d 90 01 04 30 0d 90 01 04 30 0d 90 01 04 30 0d 90 01 04 30 0d 90 01 04 30 0d 90 01 04 33 c0 eb 07 8d a4 24 00 00 00 00 30 88 90 01 04 40 83 f8 0f 90 00 } //1
		$a_01_1 = {8a 44 3e 04 3a c2 74 17 84 c0 74 13 3c 23 74 0f 8a da 80 f3 23 3a c3 74 06 32 c2 88 44 3e 04 47 3b f9 7c dc } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}