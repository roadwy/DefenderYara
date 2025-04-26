
rule Trojan_Win32_Cosmu_AC_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 8d 54 24 3c 50 52 55 ff d3 8d 44 24 1c 8d 4c 24 34 50 68 ?? ?? ?? ?? 51 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}