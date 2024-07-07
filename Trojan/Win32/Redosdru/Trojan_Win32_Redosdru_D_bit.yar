
rule Trojan_Win32_Redosdru_D_bit{
	meta:
		description = "Trojan:Win32/Redosdru.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 f8 90 01 01 88 07 47 83 fb 02 7d 90 01 01 8b c2 c1 f8 90 01 01 88 07 47 83 fb 01 7d 90 01 01 88 17 90 00 } //1
		$a_03_1 = {8a 0c 30 80 c1 90 01 01 80 f1 90 01 01 88 0c 30 40 3b c7 7c 90 00 } //1
		$a_03_2 = {8a 14 0b 30 10 8b 45 90 01 01 40 89 45 90 01 01 3b 45 90 01 01 72 9f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}