
rule Trojan_Win64_LummaStealer_TL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 c3 41 b8 05 4c 1d 48 41 bd f8 c5 1f 90 45 0f 45 c5 bf 05 4c 1d 48 41 0f 45 fc be 82 1c dd b4 41 0f 45 f7 b8 c0 73 72 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}