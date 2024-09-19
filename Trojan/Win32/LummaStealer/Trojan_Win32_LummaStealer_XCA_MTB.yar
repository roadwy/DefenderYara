
rule Trojan_Win32_LummaStealer_XCA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.XCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d1 89 4d e4 8b 4d e4 80 c1 36 8b 55 ?? 88 0c 10 ff 45 ec 8b 4d ec 83 f9 16 72 } //4
		$a_03_1 = {31 fe 89 75 e8 8b 5d e8 80 c3 d6 8b 75 ?? 88 1c 30 ff 45 f0 8b 75 f0 83 fe 06 72 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}