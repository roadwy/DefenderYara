
rule Trojan_Win32_LummaStealer_FAI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 32 1c 10 8b 45 08 32 df 30 1f 8b 55 c8 3b 4d 0c 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}