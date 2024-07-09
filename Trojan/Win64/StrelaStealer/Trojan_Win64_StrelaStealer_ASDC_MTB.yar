
rule Trojan_Win64_StrelaStealer_ASDC_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 41 57 41 56 41 55 41 54 56 57 53 b8 ?? ?? 00 00 e8 [0-03] 00 48 29 c4 48 8d ac 24 80 00 00 00 31 c0 8b 0d a3 ?? ?? 00 8b 15 a9 ?? ?? 00 41 89 [0-08] 41 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}