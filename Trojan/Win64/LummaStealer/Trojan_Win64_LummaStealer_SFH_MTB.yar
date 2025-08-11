
rule Trojan_Win64_LummaStealer_SFH_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.SFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 45 34 42 80 34 30 44 8b 45 34 83 c0 01 89 45 2c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}