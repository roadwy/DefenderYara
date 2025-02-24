
rule Trojan_Win32_LummaStealer_SBD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 c3 01 74 60 e0 4e b7 83 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}