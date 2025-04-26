
rule Trojan_Win32_Vidar_NR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 8c 8d 0c 03 33 d2 8b c3 f7 75 88 8b 85 ?? ?? ?? ?? 57 8a 04 02 8b 55 80 32 04 0a 88 01 8d 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}