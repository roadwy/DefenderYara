
rule Trojan_Win64_MeduzaStealer_CCAF_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.CCAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e3 d1 ea 8d 0c 52 3b d9 48 8d 15 ?? ?? ?? ?? 48 8b cf 74 } //1
		$a_01_1 = {4d 65 64 75 5a 5a 5a 61 } //1 MeduZZZa
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}