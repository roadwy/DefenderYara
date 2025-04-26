
rule Trojan_Win32_Androm_VD_MTB{
	meta:
		description = "Trojan:Win32/Androm.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b de 03 d9 [0-40] 8b c1 bf ?? ?? ?? ?? 33 d2 f7 f7 85 d2 [0-40] 80 33 [0-40] 41 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}