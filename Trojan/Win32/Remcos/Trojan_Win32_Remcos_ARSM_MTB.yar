
rule Trojan_Win32_Remcos_ARSM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 30 f1 46 00 68 f0 ea 46 00 ff d7 50 ff d6 68 48 f1 46 00 bd 94 ee 46 00 a3 30 7b 47 00 55 ff d7 50 ff d6 68 60 f1 46 00 55 a3 1c 7b 47 00 ff d3 50 ff d6 68 70 f1 46 00 55 a3 28 7b 47 00 ff d3 50 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}