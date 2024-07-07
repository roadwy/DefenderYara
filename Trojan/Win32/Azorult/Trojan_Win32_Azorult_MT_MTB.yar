
rule Trojan_Win32_Azorult_MT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 03 90 02 05 03 90 02 05 8d 90 02 02 33 90 01 01 33 90 01 01 89 90 02 02 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 02 81 3d 90 02 08 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}