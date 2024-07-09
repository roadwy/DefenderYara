
rule Trojan_Win32_Gozi_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 fb c3 14 0c 18 89 2d ?? ?? ?? ?? 7c c6 90 09 25 00 [0-20] 55 55 55 55 55 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}