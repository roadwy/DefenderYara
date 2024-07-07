
rule Trojan_Win64_StrelaStealer_GPAK_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 09 f2 44 09 df 41 31 fa 45 89 d3 41 83 f3 ff 89 ce 44 31 de 21 ce 45 89 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}