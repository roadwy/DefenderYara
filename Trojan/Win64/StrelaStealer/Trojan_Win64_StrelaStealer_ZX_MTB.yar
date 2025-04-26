
rule Trojan_Win64_StrelaStealer_ZX_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 b8 06 00 00 48 8b 8d 20 01 00 00 48 8b 11 48 8b 8d b0 06 00 00 48 83 ec 20 48 89 4d 80 48 89 c1 48 8b 45 80 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}