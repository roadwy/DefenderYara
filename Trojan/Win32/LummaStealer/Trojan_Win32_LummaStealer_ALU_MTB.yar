
rule Trojan_Win32_LummaStealer_ALU_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 cf 66 de 19 89 d6 21 ce 89 d3 31 cb f7 d1 09 ca 29 d1 01 f1 8d 0c 4b 89 4d ec 8b 4d ec 80 c1 f5 8b 55 f0 88 4c 15 d0 ff 45 f0 8b 4d f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}