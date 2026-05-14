
rule Trojan_Win32_LummaStealer_PAA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 24 8b ac 24 80 00 00 00 32 0c 07 8b 44 24 18 32 0c 07 32 0b 32 4c 24 12 8b 44 24 74 88 0b 8b 4c 24 6c 3b 54 24 78 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}