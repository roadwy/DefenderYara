
rule Trojan_Win64_SantaStealer_PS_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 54 05 00 41 30 14 06 48 83 c0 01 48 3b 45 28 72 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}