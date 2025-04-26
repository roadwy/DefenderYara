
rule Trojan_Win64_StrelaStealer_ASR_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 4c 01 c0 48 8b 40 08 48 8d 55 f8 49 89 d1 45 89 d0 48 89 ca 48 89 c1 48 8b 05 49 72 02 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}