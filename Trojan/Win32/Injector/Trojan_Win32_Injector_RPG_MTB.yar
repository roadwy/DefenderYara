
rule Trojan_Win32_Injector_RPG_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 18 81 c2 9f bd 7a b1 40 81 ee 01 00 00 00 81 ee 44 84 a8 a5 39 c8 75 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}