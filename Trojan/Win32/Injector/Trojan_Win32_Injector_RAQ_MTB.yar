
rule Trojan_Win32_Injector_RAQ_MTB{
	meta:
		description = "Trojan:Win32/Injector.RAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f4 01 00 00 75 05 [0-20] c3 90 09 80 00 [0-20] e8 ?? 00 00 00 [0-20] 31 [0-20] 39 ?? (7c|75) [0-20] c3 [0-20] 8d [0-20] 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}