
rule Trojan_Win32_Ekstak_DE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 30 41 00 14 05 50 55 49 4e 54 f8 10 40 00 02 00 00 00 00 c0 30 41 00 14 0a 50 4c 69 73 74 45 6e 74 72 79 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}