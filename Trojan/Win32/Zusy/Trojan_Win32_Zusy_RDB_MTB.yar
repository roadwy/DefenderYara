
rule Trojan_Win32_Zusy_RDB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 28 23 d1 0f af 15 44 a0 40 00 32 c3 89 0d 48 a0 40 00 2a c3 89 15 4c a0 40 00 32 c3 83 c4 0c 02 c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}