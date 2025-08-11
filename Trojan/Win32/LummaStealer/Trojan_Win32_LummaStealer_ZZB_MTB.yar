
rule Trojan_Win32_LummaStealer_ZZB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b6 0e 8d 51 f7 83 fa 17 77 08 0f a3 d0 73 03 46 eb ed 89 34 24 80 f9 7d 0f 85 cc 01 00 00 46 85 db 74 06 8b 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}