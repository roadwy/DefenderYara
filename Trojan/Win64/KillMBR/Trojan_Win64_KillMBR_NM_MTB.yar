
rule Trojan_Win64_KillMBR_NM_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 83 fe 01 75 ?? 8b 45 40 ff c8 48 89 1d cf 80 01 00 89 05 c5 80 01 00 eb ?? 48 8d 55 38 48 89 7d 38 48 8b cb } //3
		$a_01_1 = {41 50 4d 20 30 38 32 37 39 2b 35 32 35 35 2e 65 78 65 } //1 APM 08279+5255.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}