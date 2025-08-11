
rule Trojan_Win32_LummaStealer_ZFK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZFK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 f7 01 ff 29 df 8b 5d ec 09 d7 31 f2 8d 34 3f f7 d6 01 fe 09 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}