
rule Trojan_Win32_Gootkit_DSK_MTB{
	meta:
		description = "Trojan:Win32/Gootkit.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 81 ea d0 07 00 00 89 55 fc c1 4d 08 09 8b 45 fc 2d 00 10 00 00 89 45 fc 8b 4d 08 33 4d 0c 89 4d 08 8b 55 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}