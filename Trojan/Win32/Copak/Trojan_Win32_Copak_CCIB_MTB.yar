
rule Trojan_Win32_Copak_CCIB_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 db 09 d2 e8 ?? ?? ?? ?? 31 38 4b 40 29 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}