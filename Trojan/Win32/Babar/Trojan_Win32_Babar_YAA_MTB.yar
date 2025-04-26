
rule Trojan_Win32_Babar_YAA_MTB{
	meta:
		description = "Trojan:Win32/Babar.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d d4 89 d0 89 c2 8b 45 10 01 d0 0f b6 00 31 c1 89 ca 8b 45 f4 88 10 } //18
	condition:
		((#a_01_0  & 1)*18) >=18
 
}