
rule Trojan_Win32_LummaStealer_FAJ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 c4 32 1c 01 32 5d ff 88 1c 01 41 3b 4d 0c 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}