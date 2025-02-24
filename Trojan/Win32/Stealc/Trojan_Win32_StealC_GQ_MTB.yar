
rule Trojan_Win32_StealC_GQ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {1c 46 00 8a 8c 30 4b 13 01 00 8b 15 ?? 08 46 00 88 0c 32 81 3d ?? 0d 46 00 90 09 02 00 a1 } //1
		$a_01_1 = {90 04 00 00 75 56 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}