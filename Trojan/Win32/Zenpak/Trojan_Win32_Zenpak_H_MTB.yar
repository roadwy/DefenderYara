
rule Trojan_Win32_Zenpak_H_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 28 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? 01 18 8d 05 ?? ?? ?? ?? 31 38 e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zenpak_H_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d e8 0f b6 1c 07 01 f3 89 45 d8 31 f6 89 55 d4 89 f2 8b 75 f0 f7 f6 8b 75 ec 0f b6 14 16 01 d3 89 d8 99 8b 5d d4 f7 fb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}