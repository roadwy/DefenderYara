
rule Trojan_Win32_Redosdru_D_bit{
	meta:
		description = "Trojan:Win32/Redosdru.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 f8 ?? 88 07 47 83 fb 02 7d ?? 8b c2 c1 f8 ?? 88 07 47 83 fb 01 7d ?? 88 17 } //1
		$a_03_1 = {8a 0c 30 80 c1 ?? 80 f1 ?? 88 0c 30 40 3b c7 7c } //1
		$a_03_2 = {8a 14 0b 30 10 8b 45 ?? 40 89 45 ?? 3b 45 ?? 72 9f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}