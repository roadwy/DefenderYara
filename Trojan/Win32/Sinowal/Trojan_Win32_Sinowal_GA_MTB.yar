
rule Trojan_Win32_Sinowal_GA_MTB{
	meta:
		description = "Trojan:Win32/Sinowal.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a c2 32 c1 32 44 0d fc 34 cc 88 44 0d fc 41 83 f9 04 72 ec } //2
		$a_01_1 = {8a 44 0d b3 32 c1 32 02 34 48 88 44 0d b3 41 83 f9 0d 72 ec } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}