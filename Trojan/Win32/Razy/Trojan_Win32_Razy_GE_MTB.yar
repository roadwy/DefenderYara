
rule Trojan_Win32_Razy_GE_MTB{
	meta:
		description = "Trojan:Win32/Razy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {bf d8 85 40 00 01 c2 e8 ?? ?? ?? ?? 21 d2 31 3e 46 09 d2 40 39 de 75 e8 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}