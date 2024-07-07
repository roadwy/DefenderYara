
rule Trojan_Win32_Androm_VD_MTB{
	meta:
		description = "Trojan:Win32/Androm.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b de 03 d9 90 02 40 8b c1 bf 90 01 04 33 d2 f7 f7 85 d2 90 02 40 80 33 90 02 40 41 81 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}