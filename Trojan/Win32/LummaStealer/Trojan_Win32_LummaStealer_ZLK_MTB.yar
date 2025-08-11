
rule Trojan_Win32_LummaStealer_ZLK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZLK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 81 3e 4d 5a 0f 85 67 06 00 00 8b 7e 3c 81 3c 37 50 45 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}