
rule Trojan_Win32_Antavmu_GDT_MTB{
	meta:
		description = "Trojan:Win32/Antavmu.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 ef 8b 4d 08 0f b6 11 33 d0 8b 45 08 88 10 0f b6 4d ef 8b 55 08 0f b6 02 03 c1 8b 4d 08 88 01 8b 55 08 83 c2 01 89 55 08 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}