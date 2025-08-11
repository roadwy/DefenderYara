
rule Trojan_Win32_LummaStealer_ZCK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZCK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e0 82 3a 18 b3 0f 69 38 e1 82 3a 87 b5 af 5e 19 e0 82 45 04 68 83 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}