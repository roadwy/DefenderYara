
rule Trojan_Win32_Loader_BAA_MTB{
	meta:
		description = "Trojan:Win32/Loader.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 8d 0c 88 8b 45 f8 03 c2 33 d2 01 01 8b 01 b9 2a 00 00 00 89 45 f0 03 45 f8 01 04 9e 8b 04 9e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}