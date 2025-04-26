
rule Trojan_Win32_Copak_KAB_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 08 f7 d6 81 c7 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 09 ff 21 f6 31 0a 01 df 89 df 01 f3 42 89 de 21 fe 81 c0 ?? ?? ?? ?? 4f 09 fe 81 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}