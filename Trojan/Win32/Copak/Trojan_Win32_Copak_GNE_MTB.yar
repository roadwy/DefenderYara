
rule Trojan_Win32_Copak_GNE_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c9 21 f9 e8 ?? ?? ?? ?? 01 ff 21 cf 31 13 21 c9 bf ?? ?? ?? ?? 21 f9 43 21 ff 39 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}