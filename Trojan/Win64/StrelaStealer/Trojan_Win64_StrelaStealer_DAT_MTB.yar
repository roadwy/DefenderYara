
rule Trojan_Win64_StrelaStealer_DAT_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 88 de 40 80 f6 ff 40 80 e6 01 40 b7 01 41 88 fe 41 80 f6 01 45 88 df 45 20 f7 44 08 fe } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}