
rule Trojan_Win64_LummaStealer_NS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 0a 0f 83 ee 0e fc ff 66 41 89 01 48 8d 64 24 ?? e9 f5 31 fc ff } //3
		$a_03_1 = {e8 51 3c fd ff 33 c9 48 f7 54 24 ?? 4d 85 d2 48 8d 64 24 ?? 0f 84 74 7d fe ff } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}