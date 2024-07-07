
rule Trojan_Win32_Ekstak_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 54 06 ff 8a 92 20 20 52 01 33 c9 8a 4c 07 ff 8a 00 20 20 52 00 3a ca 74 0c 33 c0 8a c2 33 01 8a d1 2b c2 eb 0b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}