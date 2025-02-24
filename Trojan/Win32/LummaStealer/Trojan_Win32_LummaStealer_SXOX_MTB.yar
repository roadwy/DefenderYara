
rule Trojan_Win32_LummaStealer_SXOX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SXOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 8d 0c 3a 8b 45 f0 c1 e8 05 89 45 fc 8b 45 dc 01 45 fc 33 f1 81 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}