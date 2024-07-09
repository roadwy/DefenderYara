
rule Trojan_Win32_Phorpiex_MLN_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.MLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 03 e8 ?? ?? ?? ?? 30 06 83 6d ?? 01 39 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}