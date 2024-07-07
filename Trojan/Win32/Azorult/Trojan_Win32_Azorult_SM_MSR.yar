
rule Trojan_Win32_Azorult_SM_MSR{
	meta:
		description = "Trojan:Win32/Azorult.SM!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 10 03 f5 8d 0c 3b 33 f1 } //1
		$a_01_1 = {8b 84 24 38 04 00 00 8b 4c 24 14 89 78 04 5f 5e 5d 89 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}