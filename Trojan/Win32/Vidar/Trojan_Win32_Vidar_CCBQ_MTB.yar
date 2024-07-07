
rule Trojan_Win32_Vidar_CCBQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CCBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 55 d8 8b 45 f0 31 45 fc 33 55 fc 81 3d } //1
		$a_01_1 = {d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 5d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}