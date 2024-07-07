
rule Trojan_Win32_Farfli_DSK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}