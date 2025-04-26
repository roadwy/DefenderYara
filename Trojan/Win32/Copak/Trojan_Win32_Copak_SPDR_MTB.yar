
rule Trojan_Win32_Copak_SPDR_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 83 c4 04 21 f7 e8 ?? ?? ?? ?? 31 0a 46 4f 42 bf ?? ?? ?? ?? 29 fe 39 da 75 d9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}