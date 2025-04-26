
rule Trojan_Win32_LummaStealer_SPD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 e8 8b 45 f4 33 45 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}