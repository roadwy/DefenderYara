
rule Trojan_Win32_PonyStealer_GTT_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {21 fc 97 31 48 cf 0c ff 3c a2 6b bb } //5
		$a_03_1 = {d0 31 33 07 d0 b4 68 ?? ?? ?? ?? c4 00 } //5
		$a_80_2 = {42 72 61 67 67 61 74 30 } //Braggat0  1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}