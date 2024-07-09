
rule Trojan_Win32_Vidar_VOT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c2 9e 09 00 00 2b 55 a0 2b d0 8b 45 d8 31 10 83 45 ec ?? 83 45 d8 04 8b 45 ec 3b 45 d4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}