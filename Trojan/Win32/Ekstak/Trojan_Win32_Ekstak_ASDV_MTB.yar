
rule Trojan_Win32_Ekstak_ASDV_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ec 9f 66 00 0e 04 63 00 00 be 0a 00 d4 bd 14 99 a7 bd 62 00 00 d4 00 00 e4 01 7b } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}