
rule Trojan_Win32_Redlinestealer_RW_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b4 21 e1 c5 c7 [0-05] ff ff ff ff 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8b 4c 24 ?? 81 c7 47 86 c8 61 83 6c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}