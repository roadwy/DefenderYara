
rule Trojan_Win32_LummaStealer_NSE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b d2 28 8b 85 5c ff ff ff 8b 4c 10 90 01 01 89 8d e4 fe ff ff 8b 95 90 01 04 81 e2 00 00 00 40 74 27 90 00 } //3
		$a_03_1 = {eb 0f 8b 95 90 01 04 83 c2 01 89 95 90 01 04 8b 85 68 ff ff ff 0f b7 48 06 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}