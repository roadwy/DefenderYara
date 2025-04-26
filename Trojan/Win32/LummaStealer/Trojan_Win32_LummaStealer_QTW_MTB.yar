
rule Trojan_Win32_LummaStealer_QTW_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.QTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 b0 8b 44 24 24 81 c2 ?? ?? ?? ?? 8b 4c b0 04 8b 44 24 3c 8a 04 01 8d 4c 24 24 30 02 e8 ?? ?? ?? ?? 8d 4c 24 48 e8 ?? ?? ?? ?? 8d 4c 24 30 e8 ?? ?? ?? ?? 8d 4c 24 3c e8 ?? ?? ?? ?? 8b 44 24 18 47 89 7c 24 14 81 ff 00 2c 12 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}