
rule Trojan_Win32_LummaStealer_FAK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c4 32 5d ff 8b 55 c8 30 18 8b 5d 14 8b 45 08 3b 4d 0c 72 a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}