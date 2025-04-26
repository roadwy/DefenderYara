
rule Trojan_Win32_LummaStealer_CCHX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 04 31 83 ff 0f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}