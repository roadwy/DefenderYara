
rule Trojan_Win32_Dridex_ED_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ED!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 8b 45 08 8a 08 8a 55 f3 80 e2 18 0f be c1 88 55 f3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}