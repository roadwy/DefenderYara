
rule Trojan_Win32_Ekstak_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 69 bf 6b 00 f7 2d 68 00 00 a2 0a 00 06 15 a8 0e 36 d5 67 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}