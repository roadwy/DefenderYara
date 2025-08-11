
rule Trojan_Win32_LummaStealer_GVF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c7 2b cd f7 de 81 f1 60 9b b7 35 03 dd 87 c6 33 d0 81 eb 7c 09 51 1b 83 c1 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}