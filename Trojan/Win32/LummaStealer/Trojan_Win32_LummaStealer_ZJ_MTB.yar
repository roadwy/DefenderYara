
rule Trojan_Win32_LummaStealer_ZJ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 6b 0d 5e 4b 47 ee 08 e3 8f ec a1 4b 76 67 87 ab c1 9c 27 28 b7 54 7a 67 d7 8a 84 e5 e0 fe ef 1c 27 a6 f6 0e 17 47 d6 7a ca 99 91 b2 02 da 81 05 34 3e 68 9d 69 b9 f5 cb f5 7f d2 12 86 a6 67 91 41 a9 4d ec af 6b a9 9b 61 90 fd ac 8e be ad f1 58 bd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}