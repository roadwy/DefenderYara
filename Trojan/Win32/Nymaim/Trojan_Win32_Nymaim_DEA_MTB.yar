
rule Trojan_Win32_Nymaim_DEA_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.DEA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 2b 13 f7 da 83 eb fc 83 c2 dd 01 f2 4a 29 f6 01 d6 c6 07 00 01 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}