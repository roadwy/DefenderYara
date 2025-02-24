
rule Trojan_Win32_LummaStealer_RPM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 0c b7 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b 31 ca 69 4c b7 04 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}