
rule Trojan_Win32_Vidar_SVD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 a8 05 ?? ?? ?? ?? 2b 45 a0 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 83 45 d8 04 8b 45 ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}