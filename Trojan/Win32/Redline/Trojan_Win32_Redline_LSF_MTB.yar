
rule Trojan_Win32_Redline_LSF_MTB{
	meta:
		description = "Trojan:Win32/Redline.LSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 25 ?? ?? ?? ?? ?? c1 e1 ?? 03 cf 33 4d ?? 8d 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}