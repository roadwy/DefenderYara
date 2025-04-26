
rule Trojan_Win32_Sfone_KAA_MTB{
	meta:
		description = "Trojan:Win32/Sfone.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 0d 83 c2 01 83 c1 01 eb ec 19 c0 83 d8 ff 85 c0 0f 84 9c 00 00 00 b9 80 6f 41 00 ba e0 c9 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}