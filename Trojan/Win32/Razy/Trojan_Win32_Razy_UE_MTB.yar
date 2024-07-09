
rule Trojan_Win32_Razy_UE_MTB{
	meta:
		description = "Trojan:Win32/Razy.UE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 3e 21 c2 29 c2 81 c6 ?? ?? ?? ?? 39 ce ?? ?? 29 d2 c3 09 da } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}