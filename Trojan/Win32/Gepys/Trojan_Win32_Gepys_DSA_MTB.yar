
rule Trojan_Win32_Gepys_DSA_MTB{
	meta:
		description = "Trojan:Win32/Gepys.DSA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 38 80 cf 01 88 d8 f6 e7 8a 3e 28 c7 88 d9 0f b6 02 d3 f8 88 f9 88 06 88 d8 d2 e0 00 c7 88 3a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}