
rule Trojan_Win32_Ekstak_SPVF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.SPVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 af 52 5d 00 4a aa 59 00 00 da 0a 00 a7 ae 66 31 c7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}