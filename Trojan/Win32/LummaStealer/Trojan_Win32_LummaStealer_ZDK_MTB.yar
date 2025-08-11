
rule Trojan_Win32_LummaStealer_ZDK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZDK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d9 67 85 d1 9d 06 eb 82 9d 06 eb 82 9d 06 eb 82 4e 74 e8 83 91 06 eb 82 4e 74 ee 83 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}