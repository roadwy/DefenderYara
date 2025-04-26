
rule Trojan_Win32_Stealer_SA_MTB{
	meta:
		description = "Trojan:Win32/Stealer.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 14 0f 03 c1 30 10 41 83 f9 ?? 72 } //1
		$a_01_1 = {8a 4c 05 dc 30 0c 07 40 83 f8 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}