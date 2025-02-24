
rule Trojan_Win32_Graftor_BAA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 55 e4 8b 45 e4 8d 8c 10 54 1e 00 00 03 4d e4 89 4d e4 8b 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}