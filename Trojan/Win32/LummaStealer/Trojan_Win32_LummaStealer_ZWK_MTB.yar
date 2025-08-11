
rule Trojan_Win32_LummaStealer_ZWK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZWK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 7c 19 d4 af 9b 62 b1 4f db 10 a2 a8 1c 4e f7 b2 33 05 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}