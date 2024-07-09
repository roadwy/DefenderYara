
rule Trojan_Win32_LummaStealer_CCFZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 83 e9 01 89 4d f4 8b 55 fc 33 55 f4 89 95 ?? ?? ?? ?? 8b 45 f4 83 e8 01 89 45 f4 83 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}