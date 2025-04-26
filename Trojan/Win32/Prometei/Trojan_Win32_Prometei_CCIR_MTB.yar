
rule Trojan_Win32_Prometei_CCIR_MTB{
	meta:
		description = "Trojan:Win32/Prometei.CCIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a d9 02 da 30 18 85 c9 74 ?? 40 8d 98 ?? ?? ?? ?? 49 03 d7 3b de 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}