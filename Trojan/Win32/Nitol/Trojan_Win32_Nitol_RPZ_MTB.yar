
rule Trojan_Win32_Nitol_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Nitol.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 54 ca 00 00 20 68 f8 4c 42 00 68 01 01 00 00 e8 e6 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}